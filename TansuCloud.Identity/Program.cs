using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication; // added for ChallengeAsync
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer; // added for bearer auth
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Npgsql;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Prometheus;
using TansuCloud.Identity;

var builder = WebApplication.CreateBuilder(args);

// Options to build a connection string from env/config
builder.Services.AddOptions<DbOptions>()
    .Bind(builder.Configuration.GetSection("Npgsql"))
    .ValidateOnStart();

builder.Services.AddDbContext<AppDbContext>((sp, opts) =>
{
    var cfg = sp.GetRequiredService<IOptions<DbOptions>>().Value;
    var cs = cfg.BuildConnectionString(builder.Configuration);
    opts.UseNpgsql(cs, npgsql =>
    {
        npgsql.EnableRetryOnFailure();
    });
    opts.EnableSensitiveDataLogging(false);
    opts.UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking);
});

builder.Services
    .AddIdentityCore<ApplicationUser>(o =>
    {
        o.User.RequireUniqueEmail = true;
        o.Password.RequireNonAlphanumeric = false;
        o.Password.RequireUppercase = false;
        o.Password.RequireLowercase = true;
        o.Password.RequiredLength = 8;
    })
    .AddRoles<IdentityRole<Guid>>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddSignInManager();

// Authentication: set JWT as default (for [Authorize] challenges)
builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddCookie(IdentityConstants.ApplicationScheme, o =>
    {
        o.LoginPath = "/dev/login"; // dev-only
    })
    .AddJwtBearer(options =>
    {
        options.Authority = builder.Configuration["Identity:Authority"] ?? "http://tansucloud.identity:8080";
        options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
        options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
        {
            ValidateAudience = false,
            NameClaimType = ClaimTypes.Name,
            RoleClaimType = ClaimTypes.Role
        };
    });

builder.Services.AddAuthorization();

builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<AppDbContext>();
    })
    .AddServer(options =>
    {
        options.AllowAuthorizationCodeFlow().RequireProofKeyForCodeExchange();
        options.AllowClientCredentialsFlow();
        options.AllowRefreshTokenFlow();
        if (builder.Environment.IsDevelopment())
        {
            options.AllowPasswordFlow(); // dev convenience only
        }

        options.SetAuthorizationEndpointUris("/connect/authorize");
        options.SetTokenEndpointUris("/connect/token");
        options.SetRevocationEndpointUris("/connect/revocation");
        options.SetConfigurationEndpointUris("/.well-known/openid-configuration");

        options.RegisterScopes(OpenIddictConstants.Scopes.OpenId,
                               OpenIddictConstants.Scopes.Email,
                               OpenIddictConstants.Scopes.Profile,
                               OpenIddictConstants.Scopes.Roles,
                               OpenIddictConstants.Scopes.OfflineAccess);

        // Token lifetimes
        options.SetAccessTokenLifetime(TimeSpan.FromMinutes(15));
        options.SetRefreshTokenLifetime(TimeSpan.FromDays(30));

        // Signing/encryption keys: prefer real certificates in non-dev
        var signingPath = builder.Configuration["Signing:CertificatePath"];
        var signingPassword = builder.Configuration["Signing:CertificatePassword"];
        var encryptionPath = builder.Configuration["Encryption:CertificatePath"];
        var encryptionPassword = builder.Configuration["Encryption:CertificatePassword"];
        if (!builder.Environment.IsDevelopment() && !string.IsNullOrWhiteSpace(signingPath))
        {
            var signingCert = !string.IsNullOrWhiteSpace(signingPassword)
                ? new X509Certificate2(signingPath!, signingPassword)
                : new X509Certificate2(signingPath!);
            options.AddSigningCertificate(signingCert);
        }
        else
        {
            options.AddDevelopmentSigningCertificate();
        }
        if (!builder.Environment.IsDevelopment() && !string.IsNullOrWhiteSpace(encryptionPath))
        {
            var encryptionCert = !string.IsNullOrWhiteSpace(encryptionPassword)
                ? new X509Certificate2(encryptionPath!, encryptionPassword)
                : new X509Certificate2(encryptionPath!);
            options.AddEncryptionCertificate(encryptionCert);
        }
        else
        {
            options.AddDevelopmentEncryptionCertificate();
        }

        options.DisableAccessTokenEncryption();

        options.UseAspNetCore();

        if (builder.Environment.IsDevelopment())
        {
            options.UseAspNetCore().DisableTransportSecurityRequirement();
        }
    });

builder.Services.AddHealthChecks();

// Seed dev data (DB, OpenIddict app, test user + Admin role)
builder.Services.AddHostedService<DevSeedHostedService>();

var app = builder.Build();

app.UseExceptionHandler(_ => { });
app.UseStatusCodePages();

// Prometheus HTTP metrics and /metrics endpoint
app.UseHttpMetrics();
app.MapMetrics();

app.UseAuthentication();
app.UseAuthorization();

app.MapHealthChecks("/health");

// dev logout to clear cookie
app.MapPost("/dev/logout", async (SignInManager<ApplicationUser> signInManager) =>
{
    await signInManager.SignOutAsync();
    return Results.Ok(new { signedOut = true });
}).AllowAnonymous();

// Dev sign-in endpoint to facilitate cookie-based auth in dev
app.MapPost("/dev/login", async (SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager) =>
{
    var user = await userManager.FindByEmailAsync("admin@local");
    if (user is null) return Results.Unauthorized();

    var claims = new List<Claim>();
    if (user.TenantId is Guid tid)
    {
        claims.Add(new Claim("tenant_id", tid.ToString()));
    }

    if (claims.Count > 0)
        await signInManager.SignInWithClaimsAsync(user, isPersistent: false, claims);
    else
        await signInManager.SignInAsync(user, isPersistent: false);

    return Results.Ok(new { signedIn = true });
}).AllowAnonymous();

app.MapGet("/auth/me", (ClaimsPrincipal user) =>
{
    if (user?.Identity?.IsAuthenticated != true)
        return Results.Unauthorized();

    var claims = user.Claims.Select(c => new { c.Type, c.Value });
    return Results.Ok(new { name = user.Identity!.Name, claims });
});

// Admin-protected test endpoint (will be routed via Gateway with JWT)
app.MapGet("/admin/ping", () => Results.Ok(new { admin = true }))
   .RequireAuthorization(policy => policy.RequireRole("Admin"));

// Echo endpoint to verify X-Tenant-Id propagation through Gateway
app.MapGet("/echo/tenant-header", (HttpContext ctx) =>
{
    var header = ctx.Request.Headers["X-Tenant-Id"].ToString();
    return Results.Ok(new { tenantHeader = header });
});

app.MapGet("/tenants", (ClaimsPrincipal user) =>
{
    // For Phase 1, return current tenant from claim if present.
    var tenant = user.FindFirst("tenant_id")?.Value;
    return Results.Ok(new { current = tenant, items = tenant is null ? Array.Empty<string>() : new[] { tenant } });
});

app.Run();

namespace TansuCloud.Identity
{
    public sealed class DbOptions
    {
        public string? Host { get; set; }
        public int? Port { get; set; }
        public string? Database { get; set; }
        public string? Username { get; set; }
        public string? Password { get; set; }
        public int? MaximumPoolSize { get; set; } = 50;

        public string BuildConnectionString(IConfiguration config)
        {
            var inContainer = string.Equals(Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER"), "true", StringComparison.OrdinalIgnoreCase);

            // Prefer ConnectionStrings:Default only when NOT running in container (so VS host can use localhost)
            var fromConnStr = !inContainer ? config.GetConnectionString("Default") : null;
            if (!string.IsNullOrWhiteSpace(fromConnStr)) return AppendPgBouncerSafeOptions(fromConnStr!);

            // Build from options/env
            var host = Host ?? config["NPGSQL__HOST"] ?? (inContainer ? "db" : "localhost");
            var port = Port.HasValue ? Port.Value : (int.TryParse(config["NPGSQL__PORT"], out var p) ? p : 5432);
            var db = Database ?? config["NPGSQL__DATABASE"] ?? "tansucloud";
            var user = Username ?? config["NPGSQL__USERNAME"] ?? "app_user";
            var pass = Password ?? config["NPGSQL__PASSWORD"] ?? "postgres";

            var b = new Npgsql.NpgsqlConnectionStringBuilder
            {
                Host = host,
                Port = port,
                Database = db,
                Username = user,
                Password = pass,
                Pooling = true,
                MaxPoolSize = (MaximumPoolSize is > 0) ? (int)MaximumPoolSize! : 50,
                TcpKeepAlive = true,
                NoResetOnClose = true,
                Multiplexing = true,
                Enlist = false
            };

            // Disable auto-prepare for PgBouncer transaction pooling by setting Max Auto Prepare=0
            b["Max Auto Prepare"] = 0;

            return b.ToString();
        }

        private static string AppendPgBouncerSafeOptions(string cs)
        {
            var b = new Npgsql.NpgsqlConnectionStringBuilder(cs)
            {
                Pooling = true,
                TcpKeepAlive = true,
                NoResetOnClose = true,
                Multiplexing = true,
                Enlist = false
            };
            // Disable auto-prepare for PgBouncer transaction pooling by setting Max Auto Prepare=0
            b["Max Auto Prepare"] = 0;
            return b.ToString();
        }
    } // End of Class DbOptions

    public sealed class ApplicationUser : Microsoft.AspNetCore.Identity.IdentityUser<System.Guid>
    {
        public System.Guid? TenantId { get; set; }
    } // End of Class ApplicationUser

    public sealed class AppDbContext : Microsoft.AspNetCore.Identity.EntityFrameworkCore.IdentityDbContext<ApplicationUser, Microsoft.AspNetCore.Identity.IdentityRole<System.Guid>, System.Guid>
    {
        public AppDbContext(Microsoft.EntityFrameworkCore.DbContextOptions<AppDbContext> options) : base(options) { } // End of Constructor

        protected override void OnModelCreating(Microsoft.EntityFrameworkCore.ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            builder.UseOpenIddict();
        }
    } // End of Class AppDbContext

    internal sealed class DevSeedHostedService : Microsoft.Extensions.Hosting.IHostedService
    {
        private readonly System.IServiceProvider _sp;
        private readonly Microsoft.Extensions.Logging.ILogger<DevSeedHostedService> _logger;
        private System.Threading.Tasks.Task? _seeding; // background task

        public DevSeedHostedService(System.IServiceProvider sp, Microsoft.Extensions.Logging.ILogger<DevSeedHostedService> logger)
        {
            _sp = sp;
            _logger = logger;
        } // End of Constructor DevSeedHostedService

        public System.Threading.Tasks.Task StartAsync(System.Threading.CancellationToken cancellationToken)
        {
            // Run seeding in background so app can start and expose /health and /metrics
            _seeding = SeedAsync(cancellationToken);
            return System.Threading.Tasks.Task.CompletedTask;
        }

        private async System.Threading.Tasks.Task SeedAsync(System.Threading.CancellationToken cancellationToken)
        {
            using var scope = _sp.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

            // Wait for DB readiness (retry)
            var attempts = 0;
            while (attempts < 30 && !cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await db.Database.EnsureCreatedAsync(cancellationToken);
                    break;
                }
                catch (System.Exception ex)
                {
                    attempts++;
                    _logger.LogWarning(ex, "Waiting for database... attempt {Attempt}/30", attempts);
                    await System.Threading.Tasks.Task.Delay(System.TimeSpan.FromSeconds(2), cancellationToken);
                }
            }

            try
            {
                var appManager = scope.ServiceProvider.GetRequiredService<OpenIddict.Abstractions.IOpenIddictApplicationManager>();
                var scopeManager = scope.ServiceProvider.GetRequiredService<OpenIddict.Abstractions.IOpenIddictScopeManager>();
                var userManager = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<ApplicationUser>>();
                var roleManager = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Identity.RoleManager<IdentityRole<Guid>>>();

                // Seed OpenIddict application for Dashboard (dev)
                var clientId = "dashboard";
                var existingApp = await appManager.FindByClientIdAsync(clientId, cancellationToken);
                var descriptor = new OpenIddict.Abstractions.OpenIddictApplicationDescriptor
                {
                    ClientId = clientId,
                    ClientSecret = "dev_secret", // dev only
                    DisplayName = "TansuCloud Dashboard",
                    RedirectUris = { new System.Uri("http://localhost:8080/signin-oidc") },
                    PostLogoutRedirectUris = { new System.Uri("http://localhost:8080/signout-callback-oidc") },
                    // Explicitly set required types to avoid validation issues when updating existing apps
                    ClientType = OpenIddict.Abstractions.OpenIddictConstants.ClientTypes.Confidential,
                    ApplicationType = OpenIddict.Abstractions.OpenIddictConstants.ApplicationTypes.Web
                };
                descriptor.Permissions.UnionWith(new[]
                {
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.Endpoints.Revocation,
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.ResponseTypes.Code,
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddict.Abstractions.OpenIddictConstants.Scopes.OpenId,
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddict.Abstractions.OpenIddictConstants.Scopes.Email,
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddict.Abstractions.OpenIddictConstants.Scopes.Profile,
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddict.Abstractions.OpenIddictConstants.Scopes.Roles,
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddict.Abstractions.OpenIddictConstants.Scopes.OfflineAccess
                });

                if (existingApp is null)
                {
                    await appManager.CreateAsync(descriptor, cancellationToken);
                    _logger.LogInformation("Seeded OpenIddict application {ClientId}", clientId);
                }
                else
                {
                    await appManager.UpdateAsync(existingApp, descriptor, cancellationToken);
                    _logger.LogInformation("Updated OpenIddict application {ClientId}", clientId);
                }

                // Seed a machine-to-machine client (client_credentials)
                var svcClientId = "svc-gateway";
                var existingSvc = await appManager.FindByClientIdAsync(svcClientId, cancellationToken);
                var svcDescriptor = new OpenIddict.Abstractions.OpenIddictApplicationDescriptor
                {
                    ClientId = svcClientId,
                    ClientSecret = "svc_secret", // dev only
                    DisplayName = "TansuCloud Gateway Service Client",
                    ClientType = OpenIddict.Abstractions.OpenIddictConstants.ClientTypes.Confidential
                };
                svcDescriptor.Permissions.UnionWith(new[]
                {
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.Endpoints.Revocation,
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddict.Abstractions.OpenIddictConstants.Scopes.OpenId,
                });

                if (existingSvc is null)
                {
                    await appManager.CreateAsync(svcDescriptor, cancellationToken);
                    _logger.LogInformation("Seeded service client {ClientId}", svcClientId);
                }
                else
                {
                    await appManager.UpdateAsync(existingSvc, svcDescriptor, cancellationToken);
                    _logger.LogInformation("Updated service client {ClientId}", svcClientId);
                }

                // Seed default scopes
                async System.Threading.Tasks.Task EnsureScopeAsync(string name)
                {
                    if (await scopeManager.FindByNameAsync(name, cancellationToken) is null)
                    {
                        await scopeManager.CreateAsync(new OpenIddict.Abstractions.OpenIddictScopeDescriptor
                        {
                            Name = name
                        }, cancellationToken);
                    }
                }
                await EnsureScopeAsync(OpenIddict.Abstractions.OpenIddictConstants.Scopes.OpenId);
                await EnsureScopeAsync(OpenIddict.Abstractions.OpenIddictConstants.Scopes.Email);
                await EnsureScopeAsync(OpenIddict.Abstractions.OpenIddictConstants.Scopes.Profile);
                await EnsureScopeAsync(OpenIddict.Abstractions.OpenIddictConstants.Scopes.Roles);
                await EnsureScopeAsync(OpenIddict.Abstractions.OpenIddictConstants.Scopes.OfflineAccess);

                // Seed dev user + Admin role
                const string adminRole = "Admin";
                if (!await roleManager.RoleExistsAsync(adminRole))
                    await roleManager.CreateAsync(new Microsoft.AspNetCore.Identity.IdentityRole<System.Guid>(adminRole));

                var user = await userManager.FindByEmailAsync("admin@local");
                if (user is null)
                {
                    user = new ApplicationUser
                    {
                        Id = System.Guid.NewGuid(),
                        Email = "admin@local",
                        UserName = "admin@local",
                        EmailConfirmed = true,
                        TenantId = System.Guid.Parse("11111111-1111-1111-1111-111111111111")
                    };
                    var result = await userManager.CreateAsync(user, "Pass123$!");
                    if (!result.Succeeded)
                    {
                        _logger.LogError("Failed to create dev user: {Errors}", string.Join(",", result.Errors.Select(e => e.Description)));
                    }
                }

                if (!await userManager.IsInRoleAsync(user, adminRole))
                {
                    var addRole = await userManager.AddToRoleAsync(user, adminRole);
                    if (!addRole.Succeeded)
                        _logger.LogWarning("Failed to add role {Role}: {Errors}", adminRole, string.Join(",", addRole.Errors.Select(e => e.Description)));
                }
            }
            catch (System.Exception ex)
            {
                _logger.LogError(ex, "Seeding failed");
            }
        }

        public System.Threading.Tasks.Task StopAsync(System.Threading.CancellationToken cancellationToken)
            => _seeding ?? System.Threading.Tasks.Task.CompletedTask;
    } // End of Class DevSeedHostedService
} // End of namespace
