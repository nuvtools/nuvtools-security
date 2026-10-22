using System.Text.Json.Serialization;

namespace NuvTools.Security.Verification.Twilio.Messages;

/// <summary>The fields of a Verify verification, or of a verification check, that this package reads.</summary>
internal sealed class TwilioVerification
{
    /// <summary><c>pending</c>, <c>approved</c>, <c>canceled</c>, <c>max_attempts_reached</c>, <c>deleted</c>, <c>failed</c> or <c>expired</c>.</summary>
    [JsonPropertyName("status")]
    public string? Status { get; set; }

    /// <summary>On a check, whether the code was the right one.</summary>
    [JsonPropertyName("valid")]
    public bool Valid { get; set; }
}
