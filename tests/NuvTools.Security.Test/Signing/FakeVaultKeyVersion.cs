using System.Security.Cryptography;

namespace NuvTools.Security.Test.Signing;

/// <summary>One version of the key in <see cref="FakeVault"/>, private half included.</summary>
internal sealed class FakeVaultKeyVersion(string version, DateTimeOffset createdOn) : IDisposable
{
    public string Version { get; } = version;

    public DateTimeOffset CreatedOn { get; } = createdOn;

    public bool Enabled { get; set; } = true;

    public DateTimeOffset? ExpiresOn { get; set; }

    public RSA Rsa { get; } = RSA.Create(2048);

    public void Dispose() => Rsa.Dispose();
}
