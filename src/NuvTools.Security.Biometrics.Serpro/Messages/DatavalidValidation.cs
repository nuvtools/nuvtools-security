using System.Text.Json.Serialization;

namespace NuvTools.Security.Biometrics.Serpro.Messages;

/// <summary>What a Datavalid request asks to be validated for the CPF.</summary>
internal sealed class DatavalidValidation
{
    [JsonPropertyName("biometria_facial")]
    public DatavalidFaceImage Face { get; set; } = new();
}
