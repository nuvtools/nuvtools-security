using Azure;
using Azure.Security.KeyVault.Keys;

namespace NuvTools.Security.Test.Signing;

/// <summary>The two vault calls the provider makes, answered from <see cref="FakeVault"/>.</summary>
internal sealed class FakeKeyClient(FakeVault vault) : KeyClient
{
    public override AsyncPageable<KeyProperties> GetPropertiesOfKeyVersionsAsync(string name, CancellationToken cancellationToken = default)
    {
        vault.Listings++;

        if (vault.Unreachable)
            throw new RequestFailedException(503, "The vault is unreachable.");

        var page = Page<KeyProperties>.FromValues([.. vault.Versions.Select(Describe)], continuationToken: null, response: null!);

        return AsyncPageable<KeyProperties>.FromPages([page]);
    }

    public override Task<Response<KeyVaultKey>> GetKeyAsync(string name, string? version = null, CancellationToken cancellationToken = default)
    {
        vault.KeyReads++;

        var found = vault.Find(version!);
        var key = KeyModelFactory.KeyVaultKey(Describe(found), new JsonWebKey(found.Rsa, includePrivateParameters: false));

        return Task.FromResult(Response.FromValue(key, null!));
    }

    private static KeyProperties Describe(FakeVaultKeyVersion version)
    {
        var properties = KeyModelFactory.KeyProperties(
            id: FakeVault.IdOf(version.Version),
            vaultUri: FakeVault.Address,
            name: FakeVault.KeyName,
            version: version.Version,
            createdOn: version.CreatedOn);

        properties.Enabled = version.Enabled;
        properties.ExpiresOn = version.ExpiresOn;

        return properties;
    }
}
