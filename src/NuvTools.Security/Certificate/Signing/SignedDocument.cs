namespace NuvTools.Security.Certificate.Signing;

/// <summary>A PDF the provider finished signing.</summary>
/// <param name="Content">The signed PDF.</param>
/// <param name="Signer">
/// The certificate the document was actually signed with. Compare it with the one the signature was
/// prepared for: the client chooses the certificate at signing time.
/// </param>
public sealed record SignedDocument(ReadOnlyMemory<byte> Content, CertificateDetails Signer);
