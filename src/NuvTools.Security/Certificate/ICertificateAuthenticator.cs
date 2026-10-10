namespace NuvTools.Security.Certificate;

/// <summary>
/// Authenticates a person by a digital certificate, in two steps: the server opens a challenge, the
/// client signs it with the certificate's private key, and the server validates the signature.
/// </summary>
/// <remarks>
/// The identity is read from the certificate on the server, after the provider confirmed possession of
/// the private key and the trust chain. Call <see cref="CompleteAsync"/> inside the sign-in operation
/// itself and take the identity from its result — never from a value the client sends.
/// </remarks>
public interface ICertificateAuthenticator
{
    /// <summary>
    /// Opens an authentication on the provider.
    /// </summary>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>The challenge the client signs and sends back.</returns>
    /// <exception cref="Exception">The provider could not be reached or refused the request.</exception>
    Task<CertificateChallenge> StartAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates the signed challenge and reads the certificate's subject.
    /// </summary>
    /// <param name="token">The token of the challenge the client signed.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>
    /// The authentication result. An empty token, a failed validation or a communication failure
    /// yields <see cref="CertificateAuthentication.Valid"/> = <c>false</c> (fail-closed).
    /// </returns>
    Task<CertificateAuthentication> CompleteAsync(string? token, CancellationToken cancellationToken = default);
}
