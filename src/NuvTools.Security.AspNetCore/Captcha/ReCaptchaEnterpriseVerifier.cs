using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NuvTools.Security.Captcha;

namespace NuvTools.Security.AspNetCore.Captcha;

/// <summary>
/// Verifies a reCAPTCHA Enterprise token by creating an assessment on the Google Cloud API
/// (<c>recaptchaenterprise.googleapis.com</c>). The API key never leaves the server.
/// </summary>
/// <param name="httpClient">Client used to call the assessment API.</param>
/// <param name="options">CAPTCHA configuration.</param>
/// <param name="logger">Logger for diagnostics.</param>
public sealed class ReCaptchaEnterpriseVerifier(
    HttpClient httpClient,
    IOptions<CaptchaOptions> options,
    ILogger<ReCaptchaEnterpriseVerifier> logger) : ICaptchaVerifier
{
    private readonly CaptchaOptions _options = options.Value;

    /// <inheritdoc />
    public async Task<CaptchaVerification> VerifyAsync(string? token, bool checkboxMode, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
            return new CaptchaVerification(false, 0);

        // The assessment key must match the key that produced the token: checkbox on step-up, score otherwise.
        var siteKey = checkboxMode ? _options.SiteKey : _options.ScoreSiteKey;
        var url = $"{_options.AssessmentBaseUrl.TrimEnd('/')}/projects/{_options.ProjectId}/assessments?key={_options.ApiKey}";
        var payload = new AssessmentRequest(new AssessmentEvent(token, siteKey));

        try
        {
            using var response = await httpClient.PostAsJsonAsync(url, payload, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();

            var result = await response.Content.ReadFromJsonAsync<AssessmentResponse>(cancellationToken).ConfigureAwait(false);
            var valid = result?.TokenProperties?.Valid == true;
            var score = result?.RiskAnalysis?.Score ?? 0;

            if (!valid)
                logger.LogWarning("CAPTCHA rejected by reCAPTCHA Enterprise. Reason: {Reason}.",
                    result?.TokenProperties?.InvalidReason ?? "unknown");

            return new CaptchaVerification(valid, score);
        }
        catch (Exception ex)
        {
            // Network failure or unexpected response: deny access (fail-closed) and log for diagnostics.
            logger.LogWarning(ex, "Failed to verify the CAPTCHA token against reCAPTCHA Enterprise.");
            return new CaptchaVerification(false, 0);
        }
    }

    private sealed record AssessmentRequest(
        [property: JsonPropertyName("event")] AssessmentEvent Event);

    private sealed record AssessmentEvent(
        [property: JsonPropertyName("token")] string Token,
        [property: JsonPropertyName("siteKey")] string SiteKey);

    private sealed class AssessmentResponse
    {
        [JsonPropertyName("tokenProperties")]
        public TokenPropertiesData? TokenProperties { get; set; }

        [JsonPropertyName("riskAnalysis")]
        public RiskAnalysisData? RiskAnalysis { get; set; }
    }

    private sealed class TokenPropertiesData
    {
        [JsonPropertyName("valid")]
        public bool Valid { get; set; }

        [JsonPropertyName("invalidReason")]
        public string? InvalidReason { get; set; }

        [JsonPropertyName("hostname")]
        public string? Hostname { get; set; }
    }

    private sealed class RiskAnalysisData
    {
        [JsonPropertyName("score")]
        public double Score { get; set; }
    }
}
