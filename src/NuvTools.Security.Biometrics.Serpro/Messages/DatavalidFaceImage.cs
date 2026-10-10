using System.Text.Json.Serialization;

namespace NuvTools.Security.Biometrics.Serpro.Messages;

/// <summary>The captured face sent to Datavalid.</summary>
internal sealed class DatavalidFaceImage
{
    [JsonPropertyName("formato")]
    public string Format { get; set; } = string.Empty;

    [JsonPropertyName("base64")]
    public string Base64 { get; set; } = string.Empty;
}
