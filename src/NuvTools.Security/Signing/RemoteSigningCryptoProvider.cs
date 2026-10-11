using Microsoft.IdentityModel.Tokens;

namespace NuvTools.Security.Signing;

/// <summary>
/// Answers for a <see cref="RemoteRsaSecurityKey"/>: signatures are created by the delegate, and
/// verified locally with the public parameters.
/// </summary>
internal sealed class RemoteSigningCryptoProvider(Func<byte[], byte[]> sign) : ICryptoProvider
{
    public bool IsSupportedAlgorithm(string algorithm, params object[] args)
        => algorithm == SecurityAlgorithms.RsaSha256 && args is [RemoteRsaSecurityKey, ..];

    public object Create(string algorithm, params object[] args)
    {
        var key = (RemoteRsaSecurityKey)args[0];
        var willCreateSignatures = args is [_, true, ..];

        // Verification needs nothing remote. It is given a plain key over the same public
        // parameters, so the stock provider handles it and this one is never asked to verify.
        return willCreateSignatures
            ? new RemoteSignatureProvider(key, algorithm, sign)
            : new AsymmetricSignatureProvider(new RsaSecurityKey(key.Parameters) { KeyId = key.KeyId }, algorithm, willCreateSignatures: false);
    }

    public void Release(object cryptoInstance) => (cryptoInstance as IDisposable)?.Dispose();
}
