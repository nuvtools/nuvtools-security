namespace NuvTools.Security.AspNetCore.Entra;

/// <summary>The claims of an Entra application token this package reads, by their unmapped names.</summary>
public static class EntraWorkloadClaims
{
    /// <summary>The calling application, on a v1 token.</summary>
    public const string ApplicationIdV1 = "appid";

    /// <summary>The calling application, on a v2 token.</summary>
    public const string ApplicationIdV2 = "azp";
}
