namespace NuvTools.Security.Biometrics.Serpro;

/// <summary>
/// Configuration for facial verification through SERPRO Datavalid.
/// </summary>
/// <remarks>
/// Datavalid compares the capture with the face on government record for the CPF and answers with a
/// similarity. The application decides what counts as a match through <see cref="MinSimilarity"/> and
/// <see cref="AcceptedLiveness"/>.
/// </remarks>
public sealed class DatavalidOptions
{
    /// <summary>Configuration section name this options class binds to.</summary>
    public const string SectionName = "Datavalid";

    /// <summary>Endpoint that issues the access token for the SERPRO API gateway.</summary>
    public string TokenUrl { get; set; } = "https://gateway.apiserpro.serpro.gov.br/token";

    /// <summary>Endpoint of the facial validation, which carries the contracted API version.</summary>
    public string ValidateUrl { get; set; } = "https://gateway.apiserpro.serpro.gov.br/datavalid/v4/pf-facial";

    /// <summary>Consumer key of the contract. Server-side only.</summary>
    public string ConsumerKey { get; set; } = string.Empty;

    /// <summary>Consumer secret of the contract. Server-side only — it is never exposed to the client.</summary>
    public string ConsumerSecret { get; set; } = string.Empty;

    /// <summary>
    /// Lowest similarity (0.0 to 1.0) accepted as a match. Defaults to 0.9, where SERPRO's "high
    /// probability" band begins; below it a partial face can pass.
    /// </summary>
    public double MinSimilarity { get; set; } = 0.9;

    /// <summary>
    /// Liveness values, as SERPRO reports them, that are accepted. Compared ignoring case. Empty (the
    /// default) leaves the liveness decision to SERPRO alone and only reports the value.
    /// </summary>
    /// <remarks>
    /// Set it from the values the contracted API version documents: once it holds any value, a capture
    /// whose liveness is missing or not listed is refused, whatever its similarity.
    /// </remarks>
    public IList<string> AcceptedLiveness { get; set; } = [];
}
