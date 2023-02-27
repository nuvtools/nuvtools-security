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
        if (claims == null)
            throw new ArgumentNullException(nameof(claims));

        options.AddPolicy(name, policy =>
        {
            foreach (var item in claims)
            {
                policy.RequireClaim(item.Type, item.Value);
            }
        });
    }

    public static void AddPolicyWithRequiredClaim(this AuthorizationOptions options, string name, string type, params string[] values)
    {
        if (string.IsNullOrEmpty(name))
            throw new ArgumentNullException(nameof(name));

        if (string.IsNullOrEmpty(type))
            throw new ArgumentNullException(nameof(type));

        if (values == null)
            throw new ArgumentNullException(nameof(values));

        options.AddPolicy(name, policy => policy.RequireClaim(type, values));
    }
}