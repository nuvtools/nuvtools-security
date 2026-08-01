namespace NuvTools.Security.Captcha;

/// <summary>
/// Attaches the CAPTCHA token and mode headers to an outgoing request, so the server-side filter can
/// verify them.
/// </summary>
public static class CaptchaHttpRequestExtensions
{
    /// <summary>
    /// Adds the <see cref="CaptchaDefaults.TokenHeader"/> and <see cref="CaptchaDefaults.ModeHeader"/>
    /// headers to the request. Empty values are skipped, leaving the header absent.
    /// </summary>
    /// <param name="request">The request to attach the headers to.</param>
    /// <param name="token">The token produced by the CAPTCHA provider.</param>
    /// <param name="mode">
    /// <see cref="CaptchaDefaults.ModeScore"/> or <see cref="CaptchaDefaults.ModeCheckbox"/>.
    /// </param>
    public static void AddCaptchaToken(this HttpRequestMessage request, string? token, string? mode = null)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!string.IsNullOrEmpty(token))
            request.Headers.Add(CaptchaDefaults.TokenHeader, token);

        if (!string.IsNullOrEmpty(mode))
            request.Headers.Add(CaptchaDefaults.ModeHeader, mode);
    }
}
