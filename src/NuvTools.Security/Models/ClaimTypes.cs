namespace NuvTools.Security.Models;

/// <summary>
/// Provides custom claim type URIs used by NuvTools security libraries.
/// </summary>
/// <remarks>
/// These claim types are in addition to the standard claim types provided by
/// <see cref="System.Security.Claims.ClaimTypes"/> and follow the URI-based
/// naming convention for custom claims.
/// </remarks>
public static class ClaimTypes
{
    /// <summary>
    /// The URI for a claim that specifies the permission, http://schemas.nuvtools.com/ws/2026/06/identity/claims/permission.
    /// </summary>
    /// <remarks>
    /// Use this claim type when defining permission-based authorization policies with
    /// the AuthorizationOptionsExtensions class from NuvTools.Security.AspNetCore.Extensions.
    /// </remarks>
    public const string Permission = "http://schemas.nuvtools.com/ws/2026/06/identity/claims/permission";
}