namespace NuvTools.Security.Captcha;

/// <summary>
/// Configuration for the anti-bot protection (Google reCAPTCHA Enterprise) applied to public endpoints.
/// </summary>
/// <remarks>
/// Adaptive model: a <b>score</b> key runs invisibly on every submission; when the risk is high
/// (score below <see cref="MinScore"/>), the client presents the <b>checkbox</b> key as a step-up
/// challenge. Verification creates an assessment on the reCAPTCHA Enterprise API (Google Cloud).
/// </remarks>
public sealed class CaptchaOptions
{
    /// <summary>Configuration section name this options class binds to.</summary>
    public const string SectionName = "Captcha";

    /// <summary>
    /// Enables or disables verification. Leave <c>false</c> in development and testing so no token is
    /// required; enable it in staging and production.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Google Cloud project id where the reCAPTCHA Enterprise keys were created.</summary>
    public string ProjectId { get; set; } = string.Empty;

    /// <summary>
    /// API key used to authenticate the assessment call. Server-side only — it is never exposed to
    /// the client.
    /// </summary>
    public string ApiKey { get; set; } = string.Empty;

    /// <summary>
    /// Key id of the environment's <b>score</b> (invisible) key, used in the default flow. Must be
    /// the same key configured on the client.
    /// </summary>
    public string ScoreSiteKey { get; set; } = string.Empty;

    /// <summary>
    /// Key id of the environment's <b>checkbox</b> key, used as the step-up challenge when the score
    /// is low. Must be the same key configured on the client.
    /// </summary>
    public string SiteKey { get; set; } = string.Empty;

    /// <summary>
    /// Score threshold (0.0 = likely a bot, 1.0 = likely a human). Submissions scoring at or above
    /// this value pass through; below it, the checkbox step-up is required. Defaults to 0.5.
    /// </summary>
    public double MinScore { get; set; } = 0.5;

    /// <summary>Base endpoint of the reCAPTCHA Enterprise assessment API.</summary>
    public string AssessmentBaseUrl { get; set; } = "https://recaptchaenterprise.googleapis.com/v1";

    /// <summary>
    /// Message returned to the caller when verification fails in checkbox mode. Set it from
    /// configuration to serve the application's own language.
    /// </summary>
    public string FailureMessage { get; set; } = "Security verification failed. Reload the page and try again.";
}
