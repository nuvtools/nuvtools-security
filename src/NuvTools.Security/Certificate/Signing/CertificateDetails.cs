namespace NuvTools.Security.Certificate.Signing;

/// <summary>What a certificate says about its holder and about itself.</summary>
/// <param name="Subject">Who the certificate was issued to.</param>
/// <param name="ResponsibleName">
/// The person responsible for the certificate, when it was issued to a company (ICP-Brasil).
/// </param>
/// <param name="IssuerName">The authority that issued the certificate.</param>
/// <param name="ValidUntil">When the certificate expires, when the provider reports it.</param>
/// <param name="ThumbprintSha256">SHA-256 thumbprint of the certificate, as uppercase hexadecimal.</param>
public sealed record CertificateDetails(
    CertificateSubject Subject,
    string? ResponsibleName,
    string? IssuerName,
    DateTimeOffset? ValidUntil,
    string? ThumbprintSha256);
