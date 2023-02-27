namespace NuvTools.Security.Models;

public static class ClaimTypes
{
    /// <summary>
    /// Application permission claim. E.g., NuvTools.Security.Permission.
    /// </summary>
    public const string ApplicationPermission = "{0}.permission";

    /// <summary>
    /// The URI for a claim that specifies the permission, http://schemas.nuv.tools/ws/2021/10/identity/claims/permission.
    /// </summary>
    public const string Permission = "http://schemas.nuv.tools/ws/2021/10/identity/claims/permission";
}