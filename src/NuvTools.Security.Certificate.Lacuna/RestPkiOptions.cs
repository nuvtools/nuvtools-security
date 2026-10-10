using Lacuna.RestPki.Api;

namespace NuvTools.Security.Certificate.Lacuna;

/// <summary>
/// Configuration for certificate authentication through Lacuna REST PKI.
/// </summary>
/// <remarks>
/// The signature and the trust chain are validated on the REST PKI service, so no key or licence is
/// kept locally.
/// </remarks>
public sealed class RestPkiOptions
{
    /// <summary>Configuration section name this options class binds to.</summary>
    public const string SectionName = "RestPki";

    /// <summary>Name of the security context that trusts the ICP-Brasil roots.</summary>
    public const string PkiBrazilSecurityContext = "PkiBrazil";

    /// <summary>Name of the security context that trusts Lacuna's test roots.</summary>
    public const string LacunaTestSecurityContext = "LacunaTest";

    /// <summary>Endpoint of the REST PKI service. Defaults to Lacuna's cloud.</summary>
    public string Endpoint { get; set; } = "https://pki.rest/";

    /// <summary>
    /// Access token generated in the REST PKI console. Server-side only — it is never exposed to the
    /// client.
    /// </summary>
    public string AccessToken { get; set; } = string.Empty;

    /// <summary>
    /// Which roots a certificate must chain to: <see cref="PkiBrazilSecurityContext"/> (the default),
    /// <see cref="LacunaTestSecurityContext"/>, or the id of a security context created in the REST
    /// PKI console.
    /// </summary>
    /// <remarks>
    /// <see cref="LacunaTestSecurityContext"/> accepts certificates anyone can issue. Use it in
    /// development only.
    /// </remarks>
    public string SecurityContext { get; set; } = PkiBrazilSecurityContext;

    /// <summary>Name of the basic PAdES signature policy.</summary>
    public const string BasicPadesSignaturePolicy = "Basic";

    /// <summary>
    /// Which policy a PDF is signed under: <see cref="BasicPadesSignaturePolicy"/> (the default) or the
    /// id of another PAdES signature policy REST PKI knows. Only document signing reads it.
    /// </summary>
    public string PadesSignaturePolicy { get; set; } = BasicPadesSignaturePolicy;

    /// <summary>
    /// Resolves <see cref="PadesSignaturePolicy"/> to the id REST PKI expects.
    /// </summary>
    /// <returns>The signature policy id.</returns>
    /// <exception cref="InvalidOperationException">
    /// <see cref="PadesSignaturePolicy"/> is neither a known name nor an id.
    /// </exception>
    public Guid GetPadesSignaturePolicyId()
    {
        var value = PadesSignaturePolicy?.Trim();

        if (string.IsNullOrEmpty(value) || value.Equals(BasicPadesSignaturePolicy, StringComparison.OrdinalIgnoreCase))
            return StandardPadesSignaturePolicies.Basic;

        if (Guid.TryParse(value, out var id))
            return id;

        throw new InvalidOperationException(
            $"'{value}' is not a REST PKI PAdES signature policy. Use '{BasicPadesSignaturePolicy}' or a signature policy id.");
    }

    /// <summary>
    /// Resolves <see cref="SecurityContext"/> to the id REST PKI expects.
    /// </summary>
    /// <returns>The security context id.</returns>
    /// <exception cref="InvalidOperationException">
    /// <see cref="SecurityContext"/> is neither a known name nor an id. An unknown value is refused
    /// instead of falling back, so a typo never changes which roots are trusted.
    /// </exception>
    public Guid GetSecurityContextId()
    {
        var value = SecurityContext?.Trim();

        if (string.IsNullOrEmpty(value) || value.Equals(PkiBrazilSecurityContext, StringComparison.OrdinalIgnoreCase))
            return StandardSecurityContexts.PkiBrazil;

        if (value.Equals(LacunaTestSecurityContext, StringComparison.OrdinalIgnoreCase))
            return StandardSecurityContexts.LacunaTest;

        if (Guid.TryParse(value, out var id))
            return id;

        throw new InvalidOperationException(
            $"'{value}' is not a REST PKI security context. Use '{PkiBrazilSecurityContext}', '{LacunaTestSecurityContext}' or a security context id.");
    }
}
