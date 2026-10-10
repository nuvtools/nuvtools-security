using System.Text.Json.Serialization;

namespace NuvTools.Security.Biometrics.Serpro.Messages;

/// <summary>Body of a successful Datavalid facial validation.</summary>
internal sealed class DatavalidResponse
{
    [JsonPropertyName("biometria_facial")]
    public DatavalidFaceResult? Face { get; set; }
}
