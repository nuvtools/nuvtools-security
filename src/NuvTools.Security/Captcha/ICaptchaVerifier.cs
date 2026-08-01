namespace NuvTools.Security.Captcha;

/// <summary>
/// Verifies a CAPTCHA token against the provider (Google reCAPTCHA Enterprise).
/// </summary>
public interface ICaptchaVerifier
{
    /// <summary>
    /// Creates an assessment for the token.
    /// </summary>
    /// <param name="token">The token produced by the client.</param>
    /// <param name="checkboxMode">
    /// <c>true</c> uses the checkbox key (step-up challenge); <c>false</c> uses the score key
    /// (invisible).
    /// </param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>
    /// The verification result. An empty token or a communication failure yields
    /// <see cref="CaptchaVerification.Valid"/> = <c>false</c> (fail-closed).
    /// </returns>
    Task<CaptchaVerification> VerifyAsync(string? token, bool checkboxMode, CancellationToken cancellationToken = default);
}
