using System.Text.Json.Serialization;

namespace NuvTools.Security.Biometrics.Serpro.Messages;

/// <summary>Body of the SERPRO gateway's token response.</summary>
internal sealed class DatavalidTokenResponse
{
    [JsonPropertyName("access_token")]
    public string? AccessToken { get; set; }

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }
}
