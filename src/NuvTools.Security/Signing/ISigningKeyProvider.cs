using Microsoft.IdentityModel.Tokens;

namespace NuvTools.Security.Signing;

/// <summary>
/// Supplies the keys a token issuer signs with, wherever they are kept.
/// </summary>
/// <remarks>
/// The contract is neutral on purpose: an issuer depends on this and on
/// <see cref="SigningCredentials"/>, and the package that knows a particular key store — a vault, a
/// hardware module — implements it. Changing store is changing the registration.
/// </remarks>
public interface ISigningKeyProvider
{
    /// <summary>
    /// Returns the current signing credentials.
    /// </summary>
    /// <param name="cancellationToken">Cancels the lookup.</param>
    /// <returns>
    /// The credentials in order of preference: the first is the one to sign with, and every one
    /// of them must be published, because tokens signed by the others may still be in use.
    /// Never empty.
    /// </returns>
    Task<IReadOnlyList<SigningCredentials>> GetSigningCredentialsAsync(CancellationToken cancellationToken = default);
}
