using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace NuvTools.Security.Extensions;

public static class AuthorizationOptionsExtensions
{
    public static void AddPolicyWithRequiredPermissionClaim(this AuthorizationOptions options, string name, params string[] values)
    {
        options.AddPolicyWithRequiredClaim(name, Models.ClaimTypes.Permission, values);
    }

    public static void AddPolicyWithRequiredClaim(this AuthorizationOptions options, string name, params Claim[] claims)
    {
        if (options == null) throw new ArgumentNullException(nameof(options));
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentNullException(nameof(name));
        if (claims == null || claims.Length == 0) throw new ArgumentException("At least one claim is required.", nameof(claims));

        options.AddPolicy(name, policy =>
        {
            foreach (var claim in claims)
            {
                if (string.IsNullOrWhiteSpace(claim.Type)) throw new ArgumentException("Claim type cannot be null or whitespace.");
                if (string.IsNullOrWhiteSpace(claim.Value)) throw new ArgumentException("Claim value cannot be null or whitespace.");

                policy.RequireClaim(claim.Type, claim.Value);
            }
        });
    }

    public static void AddPolicyWithRequiredClaim(this AuthorizationOptions options, string name, string type, params string[] values)
    {
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentNullException(nameof(name));
        if (string.IsNullOrWhiteSpace(type)) throw new ArgumentNullException(nameof(type));
        if (values == null || values.Length == 0) throw new ArgumentException("At least one value is required.", nameof(values));

        options.AddPolicy(name, policy => policy.RequireClaim(type, values));
    }
}