using System.Text.Json.Serialization;

namespace NuvTools.Security.Biometrics.Serpro.Messages;

/// <summary>Body of a Datavalid facial validation request.</summary>
internal sealed class DatavalidRequest
{
    [JsonPropertyName("cpf")]
    public string Cpf { get; set; } = string.Empty;

    [JsonPropertyName("validacao")]
    public DatavalidValidation Validation { get; set; } = new();
}
