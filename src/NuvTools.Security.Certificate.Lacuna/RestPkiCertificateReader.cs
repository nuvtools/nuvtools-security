using Lacuna.RestPki.Api;
using Lacuna.RestPki.Client;
using NuvTools.Common.Strings;
using NuvTools.Security.Certificate.Signing;

namespace NuvTools.Security.Certificate.Lacuna;

/// <summary>
/// Turns REST PKI's two certificate shapes — the one its explorers answer with and the one its
/// authentications and signatures carry — into the contract's.
/// </summary>
internal static class RestPkiCertificateReader
{
    public static CertificateSubject ToSubject(PKCertificate certificate)
        => new(
            NullIfBlank(certificate.SubjectName?.CommonName),
            NullIfBlank(certificate.EmailAddress),
            DigitsOrNull(certificate.PkiBrazil?.Cpf),
            DigitsOrNull(certificate.PkiBrazil?.Cnpj),
            NullIfBlank(certificate.PkiBrazil?.CompanyName));

    public static CertificateDetails ToDetails(PKCertificate certificate)
        => new(
            ToSubject(certificate),
            NullIfBlank(certificate.PkiBrazil?.Responsavel),
            NullIfBlank(certificate.IssuerName?.CommonName),
            certificate.ValidityEnd,
            NullIfBlank(certificate.ThumbprintSHA256?.HexValue)?.ToUpperInvariant());

    public static CertificateDetails ToDetails(CertificateModel certificate)
        => new(
            new CertificateSubject(
                NullIfBlank(certificate.SubjectName?.CommonName) ?? NullIfBlank(certificate.SubjectDisplayName),
                NullIfBlank(certificate.SubjectName?.EmailAddress),
                DigitsOrNull(certificate.PkiBrazil?.Cpf),
                DigitsOrNull(certificate.PkiBrazil?.Cnpj),
                NullIfBlank(certificate.PkiBrazil?.CompanyName)),
            NullIfBlank(certificate.PkiBrazil?.Responsavel),
            NullIfBlank(certificate.IssuerDisplayName) ?? NullIfBlank(certificate.IssuerName?.CommonName),
            certificate.ValidityEnd,
            certificate.BinaryThumbprintSHA256 is { Length: > 0 } thumbprint
                ? Convert.ToHexString(thumbprint)
                : NullIfBlank(certificate.ThumbprintSHA256)?.ToUpperInvariant());

    private static string? NullIfBlank(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value;

    private static string? DigitsOrNull(string? value)
        => NullIfBlank(value?.GetNumbersOnly());
}
