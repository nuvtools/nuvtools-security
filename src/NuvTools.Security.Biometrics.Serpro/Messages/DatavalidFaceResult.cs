using System.Text.Json.Serialization;

namespace NuvTools.Security.Biometrics.Serpro.Messages;

/// <summary>What Datavalid found when comparing the capture with the face on record.</summary>
internal sealed class DatavalidFaceResult
{
    [JsonPropertyName("disponivel")]
    public bool Available { get; set; }

    [JsonPropertyName("similaridade")]
    public double Similarity { get; set; }

    [JsonPropertyName("probabilidade")]
    public string? Probability { get; set; }

    [JsonPropertyName("vivacidade")]
    public string? Liveness { get; set; }
}
