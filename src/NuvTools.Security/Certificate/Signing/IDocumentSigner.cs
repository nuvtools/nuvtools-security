namespace NuvTools.Security.Certificate.Signing;

/// <summary>
/// Signs a PDF with a digital certificate whose private key stays with the person, in two steps: the
/// server prepares the document and opens a challenge, the client signs it, and the server completes
/// the signature.
/// </summary>
/// <remarks>
/// <para>
/// Whatever the application needs to know about who signed — to check it is the expected person, or to
/// print it on the document — comes from the certificate the provider read, never from a value the
/// client sends.
/// </para>
/// <para>
/// Provider failures propagate as exceptions. Signing is not an access decision, so there is no safe
/// outcome to fall back to: the caller reports that the document was not signed.
/// </para>
/// </remarks>
public interface IDocumentSigner
{
    /// <summary>
    /// Reads who a certificate was issued to, without validating it.
    /// </summary>
    /// <param name="certificate">The certificate, DER-encoded.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>What the certificate says about its holder and issuer.</returns>
    Task<CertificateDetails> ReadCertificateAsync(ReadOnlyMemory<byte> certificate, CancellationToken cancellationToken = default);

    /// <summary>
    /// Reads the certificates a document was already signed with, without validating the signatures.
    /// </summary>
    /// <param name="signedDocument">The signed PDF.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>One entry per signature, in the order the provider reports them. Document timestamps are left out.</returns>
    Task<IReadOnlyList<CertificateDetails>> GetSignersAsync(ReadOnlyMemory<byte> signedDocument, CancellationToken cancellationToken = default);

    /// <summary>
    /// Prepares the document for signing and opens the challenge the client signs.
    /// </summary>
    /// <param name="request">The PDF and, optionally, the visible stamp of this signature.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>The challenge the client signs and sends back.</returns>
    Task<DocumentSignatureChallenge> StartAsync(DocumentSignatureRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Completes the signature the client signed the challenge for.
    /// </summary>
    /// <param name="token">The token of the challenge the client signed.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>The signed PDF and the certificate it was actually signed with.</returns>
    Task<SignedDocument> CompleteAsync(string token, CancellationToken cancellationToken = default);
}
