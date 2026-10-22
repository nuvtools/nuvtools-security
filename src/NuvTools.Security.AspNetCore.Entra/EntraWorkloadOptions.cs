namespace NuvTools.Security.AspNetCore.Entra;

/// <summary>
/// Who may call as a workload: the Entra tenant that issues the tokens, the audience they must be
/// issued for, and the applications allowed to present them.
/// </summary>
/// <remarks>
/// Left incomplete, the scheme is still registered and refuses every caller. It is never silently
/// skipped: an endpoint that admitted anybody because a setting was missing is the failure this
/// scheme exists to prevent.
/// </remarks>
public class EntraWorkloadOptions
{
    /// <summary>The Entra tenant the callers' tokens are issued by.</summary>
    public string TenantId { get; set; } = string.Empty;

    /// <summary>
    /// The audience the callers ask for — the receiving API's App ID URI, such as
    /// <c>api://{tenantId}/my-api-uat</c> — exactly as it appears in the token's <c>aud</c>.
    /// </summary>
    /// <remarks>
    /// Checked, and not merely the issuer: every workload in the tenant can obtain a token from the
    /// same issuer, so the issuer alone says nothing about who the token was meant for. A managed
    /// identity is issued a v1 token, whose <c>aud</c> is the URI it asked for, so the registration
    /// must stay on v1 tokens (the default).
    /// </remarks>
    public string Audience { get; set; } = string.Empty;

    /// <summary>
    /// The application (client) IDs allowed to call — typically managed identities' — matched against
    /// the token's <c>appid</c> (v1) or <c>azp</c> (v2).
    /// </summary>
    /// <remarks>
    /// An allowlist rather than "any identity in the tenant": every app in the tenant can ask Entra
    /// for a token for any audience, so without it the check would be "is the caller anyone".
    /// </remarks>
    public IList<string> AllowedApplicationIds { get; set; } = [];

    /// <summary>Whether enough is configured for the scheme to admit anybody at all.</summary>
    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(TenantId)
        && !string.IsNullOrWhiteSpace(Audience)
        && AllowedApplicationIds.Any(id => !string.IsNullOrWhiteSpace(id));
}
