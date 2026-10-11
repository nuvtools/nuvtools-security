using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace NuvTools.Security.Signing;

/// <summary>
/// An RSA key this process holds only the public half of. Creating a signature is handed to a
/// delegate — typically a call to the vault or module that keeps the private half.
/// </summary>
/// <remarks>
/// <para>
/// It is an <see cref="RsaSecurityKey"/> so that everything that publishes or verifies with the
/// public parameters — a JWKS endpoint, a token validator — keeps working unchanged. Only the
/// creation of a signature is redirected, through the key's own
/// <see cref="SecurityKey.CryptoProviderFactory"/>.
/// </para>
/// <para>
/// Signatures are RSASSA-PKCS1-v1_5 with SHA-256 (<c>RS256</c>); the delegate receives the data to
/// sign, not a digest, and returns the signature.
/// </para>
/// </remarks>
public class RemoteRsaSecurityKey : RsaSecurityKey
{
    /// <summary>
    /// Creates the key.
    /// </summary>
    /// <param name="publicParameters">The modulus and exponent. Private parameters are not used.</param>
    /// <param name="keyId">The identifier published with the key and written to every token.</param>
    /// <param name="sign">Signs the given data with the private half and returns the signature.</param>
    public RemoteRsaSecurityKey(RSAParameters publicParameters, string keyId, Func<byte[], byte[]> sign)
        : base(new RSAParameters { Modulus = publicParameters.Modulus, Exponent = publicParameters.Exponent })
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        ArgumentNullException.ThrowIfNull(sign);

        KeyId = keyId;
        CryptoProviderFactory = new CryptoProviderFactory { CustomCryptoProvider = new RemoteSigningCryptoProvider(sign) };
    }

    /// <summary>
    /// Reports that a private key exists — elsewhere. Reporting the truth about this process would
    /// make every consumer conclude the key cannot sign.
    /// </summary>
    public override PrivateKeyStatus PrivateKeyStatus => PrivateKeyStatus.Exists;

    /// <summary>
    /// The credentials to sign a token with this key.
    /// </summary>
    public SigningCredentials ToSigningCredentials() => new(this, SecurityAlgorithms.RsaSha256);
}
