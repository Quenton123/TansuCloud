using Microsoft.AspNetCore.Authentication; // for ChallengeAsync/SignOutAsync and AuthenticationProperties
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using StackExchange.Redis;
using System.Security.Claims;
using TansuCloud.Hub.Components;

var builder = WebApplication.CreateBuilder(args);

// Persist DataProtection keys in Redis to avoid antiforgery/cookie errors after restarts (dev)
var redisConfiguration = builder.Configuration["Redis:Configuration"] ?? "redis:6379";
builder.Services.AddDataProtection()
    .PersistKeysToStackExchangeRedis(ConnectionMultiplexer.Connect(redisConfiguration), "DataProtection-Keys")
    .SetApplicationName("tansucloud.hub");

// Auth: cookie + OpenID Connect to Identity
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
{
    options.Cookie.Name = ".tansu.hub";
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.HttpOnly = true;
    options.SlidingExpiration = true;
    options.Cookie.Path = "/hub"; // ensure cookie scoped to /hub path
})
.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    // Browser-facing authority should be Gateway on localhost in dev
    options.Authority = builder.Configuration["Identity:Authority"] ?? "http://localhost:8080";
    // Inside containers, discovery can use the compose DNS name to reach Gateway
    var metadata = builder.Configuration["Identity:MetadataAddress"];
    if (!string.IsNullOrWhiteSpace(metadata))
        options.MetadataAddress = metadata;

    options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
    options.ClientId = builder.Configuration["OpenIdConnect:ClientId"] ?? "hub";
    options.ClientSecret = builder.Configuration["OpenIdConnect:ClientSecret"] ?? "dev_secret"; // dev only
    options.ResponseType = "code"; // Authorization Code + PKCE
    options.SaveTokens = false; // BFF: do not store access tokens in cookies
    options.GetClaimsFromUserInfoEndpoint = true;
    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");
    options.Scope.Add("roles");
    options.Scope.Add("offline_access");
    options.TokenValidationParameters.NameClaimType = ClaimTypes.Name;
    options.TokenValidationParameters.RoleClaimType = ClaimTypes.Role;

    // Callback paths when app is mounted under /hub via Gateway
    options.CallbackPath = "/hub/signin-oidc";
    options.SignedOutCallbackPath = "/hub/signout-callback-oidc";
});

builder.Services.AddAuthorization();

// Add services to the container (Blazor Web App)
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents()
    .AddInteractiveWebAssemblyComponents();

var app = builder.Build();

// Forwarded headers (behind Gateway) — trust all proxies (dev)
var fwd = new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost
};
fwd.KnownNetworks.Clear();
fwd.KnownProxies.Clear();
app.UseForwardedHeaders(fwd);

// Respect X-Forwarded-Prefix to set PathBase when serving under /hub
app.Use((ctx, next) =>
{
    var prefix = ctx.Request.Headers["X-Forwarded-Prefix"].ToString();
    if (!string.IsNullOrEmpty(prefix))
    {
        ctx.Request.PathBase = prefix;
    }
    return next();
});

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseWebAssemblyDebugging();
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
}

app.UseStaticFiles();
app.UseAntiforgery();

app.UseAuthentication();
app.UseAuthorization();

// Auth endpoints
app.MapGet("/hub/login", async (HttpContext ctx) =>
{
    await ctx.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties
    {
        RedirectUri = "/hub"
    });
    return Results.Empty;
});

app.MapGet("/hub/logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    await ctx.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties
    {
        RedirectUri = "/hub"
    });
    return Results.Empty;
});

// Simple auth probe
app.MapGet("/hub/auth/me", (ClaimsPrincipal user) =>
{
    if (user.Identity?.IsAuthenticated != true) return Results.Unauthorized();
    return Results.Ok(new
    {
        name = user.Identity!.Name,
        claims = user.Claims.Select(c => new { c.Type, c.Value })
    });
});

// Map Blazor components
app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode()
    .AddInteractiveWebAssemblyRenderMode()
    .AddAdditionalAssemblies(typeof(TansuCloud.Hub.Client._Imports).Assembly);

app.Run();
