using System.Diagnostics;
using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Mvc; // ProblemDetails
using Microsoft.IdentityModel.Tokens;
using Prometheus;
using TansuCloud.Gateway.Security; // Scope requirement
using Yarp.ReverseProxy.Transforms;

var builder = WebApplication.CreateBuilder(args);

// Kestrel: remove Server header and cap request body size (10 MB)
builder.WebHost.ConfigureKestrel(o =>
{
    o.AddServerHeader = false;
    o.Limits.MaxRequestBodySize = 10 * 1024 * 1024; // 10 MB
});

// Health checks
builder.Services.AddHealthChecks();

// ProblemDetails for consistent errors
builder.Services.AddProblemDetails();

var isDevelopment = builder.Environment.IsDevelopment();

// Authentication & Authorization (JWT)
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = builder.Configuration["Identity:Authority"] ?? "http://tansucloud.identity:8080";
        options.RequireHttpsMetadata = !isDevelopment;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = !isDevelopment,
            ValidAudiences = builder.Configuration.GetSection("Jwt:ValidAudiences").Get<string[]>() ?? Array.Empty<string>(),
            NameClaimType = ClaimTypes.Name,
            RoleClaimType = ClaimTypes.Role
        };
    });

// Register custom scope handler
builder.Services.AddSingleton<IAuthorizationHandler, ScopeAuthorizationHandler>();

builder.Services.AddAuthorization(options =>
{
    // Require auth by default for all endpoints unless explicitly allowed
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();

    // Allow anonymous access for proxied Identity endpoints (OIDC + dev helpers)
    options.AddPolicy("AllowAnonymous", policy => policy.RequireAssertion(_ => true));

    // Example policies for future route protections
    options.AddPolicy("RequireAdminRole", p => p.RequireRole("Admin"));
    options.AddPolicy("RequireScope:openid", p => p.Requirements.Add(new ScopeRequirement("openid")));
});

// Forwarded headers (when running behind a front proxy/load balancer)
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

// Prometheus metrics
var rateLimitRejects = Prometheus.Metrics.CreateCounter("gateway_rate_limit_rejections_total", "Total rate limit rejections", new CounterConfiguration
{
    LabelNames = new[] { "partition" }
});
var missingTenantCounter = Prometheus.Metrics.CreateCounter("gateway_missing_tenant_total", "Number of authenticated requests missing a tenant header");

// Global token-bucket rate limiting by client/user/IP with tighter bucket on /connect/*
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = async (context, token) =>
    {
        var http = context.HttpContext!;
        var baseKey = http.User.FindFirst("client_id")?.Value
            ?? http.User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? http.Connection.RemoteIpAddress?.ToString()
            ?? "anonymous";
        var isAuthPath = http.Request.Path.StartsWithSegments("/connect");
        var partition = (isAuthPath ? "auth:" : "default:") + baseKey;
        rateLimitRejects.WithLabels(partition).Inc();
        http.Response.Headers["Retry-After"] = "1";
        var problem = new ProblemDetails
        {
            Status = StatusCodes.Status429TooManyRequests,
            Title = "Too Many Requests",
            Detail = "Rate limit exceeded. Please retry after a short delay.",
            Type = "https://httpstatuses.io/429"
        };
        await http.Response.WriteAsJsonAsync(problem, cancellationToken: token);
    };

    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
    {
        var baseKey = context.User.FindFirst("client_id")?.Value
            ?? context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? context.Connection.RemoteIpAddress?.ToString()
            ?? "anonymous";
        var isAuthPath = context.Request.Path.StartsWithSegments("/connect");
        var partition = (isAuthPath ? "auth:" : "default:") + baseKey;

        return RateLimitPartition.GetTokenBucketLimiter(partition, _ =>
        {
            // Tighter limits for auth endpoints (/connect/*)
            if (isAuthPath)
            {
                return new TokenBucketRateLimiterOptions
                {
                    TokenLimit = 30,
                    TokensPerPeriod = 10,
                    ReplenishmentPeriod = TimeSpan.FromSeconds(1),
                    AutoReplenishment = true,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = 0
                };
            }

            // Default bucket for other routes
            return new TokenBucketRateLimiterOptions
            {
                TokenLimit = 100,
                TokensPerPeriod = 50,
                ReplenishmentPeriod = TimeSpan.FromSeconds(1),
                AutoReplenishment = true,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            };
        });
    });
});

// YARP Reverse Proxy with correlation header propagation
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddTransforms(builderContext =>
    {
        builderContext.AddRequestTransform(async transformContext =>
        {
            // Propagate correlation ID to downstream
            if (transformContext.HttpContext.Request.Headers.TryGetValue("X-Correlation-ID", out var cid))
            {
                transformContext.ProxyRequest.Headers.Remove("X-Correlation-ID");
                transformContext.ProxyRequest.Headers.Add("X-Correlation-ID", (IEnumerable<string>)cid);
            }
            await Task.CompletedTask; // End of transform
        });
    });

var app = builder.Build();

// ProblemDetails + exception handler
app.UseExceptionHandler();
app.UseStatusCodePages();

// Trust X-Forwarded-* when present
app.UseForwardedHeaders();

// Correlation ID middleware (prefer Activity.Id, fall back to GUID)
app.Use(async (ctx, next) =>
{
    var correlation = ctx.Request.Headers["X-Correlation-ID"].ToString();
    if (string.IsNullOrWhiteSpace(correlation))
    {
        correlation = Activity.Current?.Id ?? Guid.NewGuid().ToString("N");
        ctx.Request.Headers["X-Correlation-ID"] = correlation;
    }
    ctx.Response.OnStarting(() =>
    {
        ctx.Response.Headers["X-Correlation-ID"] = correlation;
        return Task.CompletedTask;
    });
    await next();
});

// Security headers
app.Use(async (ctx, next) =>
{
    ctx.Response.OnStarting(() =>
    {
        ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
        ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
        ctx.Response.Headers["X-Frame-Options"] = "DENY";
        if (!isDevelopment)
        {
            ctx.Response.Headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
        }
        return Task.CompletedTask;
    });
    await next();
});

// Map health and metrics endpoints (anonymous)
app.MapHealthChecks("/health").AllowAnonymous();
app.UseHttpMetrics();
app.MapMetrics("/metrics").AllowAnonymous();

app.UseAuthentication();
app.UseRateLimiter();
app.UseAuthorization();

// Logging scope enrichment
app.Use(async (ctx, next) =>
{
    var logger = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Gateway");
    var tenant = ctx.Request.Headers["X-Tenant-Id"].ToString();
    var subject = ctx.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    var clientId = ctx.User.FindFirst("client_id")?.Value;
    using (logger.BeginScope(new Dictionary<string, object>
    {
        ["correlationId"] = ctx.Request.Headers["X-Correlation-ID"].ToString(),
        ["tenantId"] = tenant,
        ["subject"] = subject ?? string.Empty,
        ["clientId"] = clientId ?? string.Empty
    }))
    {
        await next();
    }
});

// Tenant propagation and enforcement
app.Use(async (ctx, next) =>
{
    // Propagate tenant header from JWT if not already present
    if (!ctx.Request.Headers.ContainsKey("X-Tenant-Id"))
    {
        var tenantIdFromToken = ctx.User.FindFirst("tenant_id")?.Value;
        if (!string.IsNullOrWhiteSpace(tenantIdFromToken))
        {
            ctx.Request.Headers["X-Tenant-Id"] = tenantIdFromToken;
        }
    }

    // Enforce tenant presence for authenticated, non-Identity paths
    var path = ctx.Request.Path.Value ?? string.Empty;
    var isIdentityPath = path.StartsWith("/connect/") || path.StartsWith("/.well-known/") ||
                         path.StartsWith("/auth/") || path.StartsWith("/dev/") ||
                         path.StartsWith("/health") || path.StartsWith("/metrics");

    if (!isIdentityPath && ctx.User?.Identity?.IsAuthenticated == true)
    {
        var tenantHeader = ctx.Request.Headers["X-Tenant-Id"].ToString();
        if (string.IsNullOrWhiteSpace(tenantHeader))
        {
            missingTenantCounter.Inc();
            var problem = new ProblemDetails
            {
                Status = StatusCodes.Status400BadRequest,
                Title = "Missing Tenant",
                Detail = "X-Tenant-Id is required for authenticated requests.",
                Type = "https://httpstatuses.io/400"
            };
            ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
            await ctx.Response.WriteAsJsonAsync(problem);
            return;
        }
        if (!Guid.TryParse(tenantHeader, out _))
        {
            var problem = new ProblemDetails
            {
                Status = StatusCodes.Status400BadRequest,
                Title = "Invalid Tenant",
                Detail = "X-Tenant-Id must be a valid GUID.",
                Type = "https://httpstatuses.io/400"
            };
            ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
            await ctx.Response.WriteAsJsonAsync(problem);
            return;
        }
    }

    await next();
});

// Proxy
app.MapReverseProxy();

app.Run();