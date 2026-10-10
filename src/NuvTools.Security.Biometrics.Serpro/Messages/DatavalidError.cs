using System.Text.Json.Serialization;

namespace NuvTools.Security.Biometrics.Serpro.Messages;

/// <summary>
/// Body of a refused Datavalid request, for example
/// <c>{"code":"DV040","args":["FACE_NOT_IN_ORIGIN"],"link":"..."}</c>.
/// </summary>
internal sealed class DatavalidError
{
    [JsonPropertyName("code")]
    public string? Code { get; set; }
}
