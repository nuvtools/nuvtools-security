namespace NuvTools.Security.Test.Signing;

/// <summary>
/// The state behind <see cref="FakeKeyClient"/> and <see cref="FakeCryptographyClient"/>: the
/// versions of one key, and a count of what was asked of the vault.
/// </summary>
internal sealed class FakeVault : IDisposable
{
    public const string KeyName = "token-signing";

    public static readonly Uri Address = new("https://fake-vault.vault.azure.net/");

    public List<FakeVaultKeyVersion> Versions { get; } = [];

    /// <summary>When set, listing the versions fails as an unreachable vault would.</summary>
    public bool Unreachable { get; set; }

    public int Listings { get; set; }

    public int KeyReads { get; set; }

    public int Signatures { get; set; }

    public FakeVaultKeyVersion Add(string version, DateTimeOffset createdOn)
    {
        var added = new FakeVaultKeyVersion(version, createdOn);
        Versions.Add(added);
        return added;
    }

    public FakeVaultKeyVersion Find(string version) => Versions.Single(candidate => candidate.Version == version);

    public static Uri IdOf(string version) => new(Address, $"keys/{KeyName}/{version}");

    public void Dispose()
    {
        foreach (var version in Versions)
            version.Dispose();
    }
}
