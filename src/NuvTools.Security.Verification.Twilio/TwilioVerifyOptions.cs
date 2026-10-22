namespace NuvTools.Security.Verification.Twilio;

/// <summary>
/// Configuration for phone verification through Twilio Verify.
/// </summary>
/// <remarks>
/// Twilio authenticates the calls with an API key (<see cref="ApiKeySid"/> and
/// <see cref="ApiKeySecret"/>), and the Verify service (<see cref="ServiceSid"/>) holds the message
/// template, the code length and its lifetime, set once at Twilio.
/// </remarks>
public sealed class TwilioVerifyOptions
{
    /// <summary>Configuration section name this options class binds to.</summary>
    public const string SectionName = "TwilioVerify";

    /// <summary>The Verify API, ending with a slash.</summary>
    public string BaseUrl { get; set; } = "https://verify.twilio.com/v2/";

    /// <summary>SID of the API key (<c>SK…</c>), or of the account when its auth token is used instead.</summary>
    public string ApiKeySid { get; set; } = string.Empty;

    /// <summary>Secret of the API key, or the account's auth token. Server-side only.</summary>
    public string ApiKeySecret { get; set; } = string.Empty;

    /// <summary>SID of the Verify service (<c>VA…</c>) the codes are sent through.</summary>
    public string ServiceSid { get; set; } = string.Empty;

    /// <summary>Whether all three credentials are set. Without them every call answers unavailable.</summary>
    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(ApiKeySid)
        && !string.IsNullOrWhiteSpace(ApiKeySecret)
        && !string.IsNullOrWhiteSpace(ServiceSid);
}
