using System.Text.Json.Serialization;

namespace NuvTools.Security.Verification.Twilio.Messages;

/// <summary>Twilio's error body.</summary>
internal sealed class TwilioError
{
    /// <summary>Twilio's error code (https://www.twilio.com/docs/api/errors).</summary>
    [JsonPropertyName("code")]
    public int? Code { get; set; }

    /// <summary>What went wrong, in Twilio's words.</summary>
    [JsonPropertyName("message")]
    public string? Message { get; set; }
}
