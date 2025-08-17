using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace TansuCloud.Gateway.Security
{
    public sealed class ScopeRequirement : IAuthorizationRequirement
    {
        public ScopeRequirement(string scope) => Scope = scope; // End of Constructor ScopeRequirement
        public string Scope { get; } // End of Property Scope
    } // End of Class ScopeRequirement

    public sealed class ScopeAuthorizationHandler : AuthorizationHandler<ScopeRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ScopeRequirement requirement)
        {
            // Standard 'scope' or 'scp' claim used by many providers
            var scopes = context.User.FindFirst("scope")?.Value ?? context.User.FindFirst("scp")?.Value;
            if (!string.IsNullOrEmpty(scopes))
            {
                foreach (var s in scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    if (string.Equals(s, requirement.Scope, StringComparison.Ordinal))
                    {
                        context.Succeed(requirement);
                        break;
                    }
                }
            }
            return Task.CompletedTask; // End of Method HandleRequirementAsync
        }
    } // End of Class ScopeAuthorizationHandler
} // End of namespace
