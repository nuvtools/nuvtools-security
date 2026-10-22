using System.Security.Claims;

namespace NuvTools.Security.AspNetCore.Entra;

/// <summary>Reads the calling workload out of a principal the Entra workload scheme built.</summary>
public static class ClaimsPrincipalExtensions
{
    /// <summary>
    /// The application ID of the calling workload — <c>appid</c> on a v1 token, <c>azp</c> on a v2
    /// one — or <see langword="null"/> when the principal carries neither.
    /// </summary>
    public static string? GetEntraWorkloadApplicationId(this ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        return principal.FindFirst(EntraWorkloadClaims.ApplicationIdV1)?.Value
            ?? principal.FindFirst(EntraWorkloadClaims.ApplicationIdV2)?.Value;
    }
}
