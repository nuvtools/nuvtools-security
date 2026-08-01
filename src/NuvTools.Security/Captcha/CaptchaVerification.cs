namespace NuvTools.Security.Captcha;

/// <summary>Result of verifying a CAPTCHA token against the provider.</summary>
/// <param name="Valid">
/// Whether the token is valid — not expired, not already consumed, and issued by the expected key.
/// </param>
/// <param name="Score">
/// Risk analysis (0.0 = likely a bot, 1.0 = likely a human). Only meaningful in score mode.
/// </param>
public sealed record CaptchaVerification(bool Valid, double Score);
