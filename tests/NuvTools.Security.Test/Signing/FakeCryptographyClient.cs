using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using System.Security.Cryptography;

namespace NuvTools.Security.Test.Signing;

/// <summary>Signs with one version's private half, as the vault does for the real client.</summary>
internal sealed class FakeCryptographyClient(FakeVault vault, FakeVaultKeyVersion version) : CryptographyClient
{
    public override SignResult SignData(SignatureAlgorithm algorithm, byte[] data, CancellationToken cancellationToken = default)
    {
        vault.Signatures++;

        return CryptographyModelFactory.SignResult(
            keyId: FakeVault.IdOf(version.Version).ToString(),
            signature: version.Rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            algorithm: algorithm);
    }
}
