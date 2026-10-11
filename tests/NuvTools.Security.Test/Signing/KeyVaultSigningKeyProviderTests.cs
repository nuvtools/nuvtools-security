using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NuvTools.Security.Signing.Azure;
using NuvTools.Security.Test.Biometrics;
using NUnit.Framework;

namespace NuvTools.Security.Test.Signing;

[TestFixture]
public class KeyVaultSigningKeyProviderTests
{
    private FakeVault _vault = null!;
    private ManualTimeProvider _time = null!;
    private KeyVaultSigningKeyProvider _provider = null!;

    [SetUp]
    public void CreateProvider()
    {
        _vault = new FakeVault();
        _time = new ManualTimeProvider();

        _provider = new KeyVaultSigningKeyProvider(
            new FakeKeyClient(_vault),
            key => new FakeCryptographyClient(_vault, _vault.Find(key.Properties.Version)),
            Options.Create(new KeyVaultSigningOptions
            {
                VaultUri = FakeVault.Address.ToString(),
                KeyName = FakeVault.KeyName,
                ActivationDelay = TimeSpan.FromHours(1),
                RefreshInterval = TimeSpan.FromMinutes(5)
            }),
            _time,
            NullLogger<KeyVaultSigningKeyProvider>.Instance);
    }

    [TearDown]
    public void DisposeProvider()
    {
        _provider.Dispose();
        _vault.Dispose();
    }

    [Test]
    public async Task Token_IsSignedInTheVault_AndValidatesWithThePublicKey()
    {
        var version = _vault.Add("v1", _time.GetUtcNow().AddDays(-30));

        var credentials = await _provider.GetSigningCredentialsAsync();
        var token = CreateToken(credentials[0]);

        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = "https://issuer.test",
            ValidAudience = "audience",
            IssuerSigningKey = new RsaSecurityKey(version.Rsa.ExportParameters(false)) { KeyId = "v1" }
        });

        Assert.Multiple(() =>
        {
            Assert.That(result.IsValid, Is.True, result.Exception?.Message);
            Assert.That(_vault.Signatures, Is.EqualTo(1));
            Assert.That(new JsonWebToken(token).Kid, Is.EqualTo("v1"));
            Assert.That(((RsaSecurityKey)credentials[0].Key).Parameters.D, Is.Null);
        });
    }

    [Test]
    public async Task DisabledAndExpiredVersions_AreNotOffered()
    {
        _vault.Add("current", _time.GetUtcNow().AddDays(-30));
        _vault.Add("disabled", _time.GetUtcNow().AddDays(-60)).Enabled = false;
        _vault.Add("expired", _time.GetUtcNow().AddDays(-90)).ExpiresOn = _time.GetUtcNow().AddDays(-1);

        var credentials = await _provider.GetSigningCredentialsAsync();

        Assert.That(credentials.Select(credential => credential.Key.KeyId), Is.EqualTo(new[] { "current" }));
    }

    [Test]
    public async Task RotatedVersion_IsPublishedAtTheNextRefresh_AndSignsOnceTheDelayHasPassed()
    {
        _vault.Add("v1", _time.GetUtcNow().AddDays(-30));

        var before = await KeyIdsAsync();

        _vault.Add("v2", _time.GetUtcNow());

        var withinInterval = await KeyIdsAsync();

        _time.Advance(TimeSpan.FromMinutes(6));
        var published = await KeyIdsAsync();

        _time.Advance(TimeSpan.FromHours(1));
        var signing = await KeyIdsAsync();

        Assert.Multiple(() =>
        {
            Assert.That(before, Is.EqualTo(new[] { "v1" }));
            Assert.That(withinInterval, Is.EqualTo(new[] { "v1" }), "The list is reused within the refresh interval.");
            Assert.That(published, Is.EqualTo(new[] { "v1", "v2" }));
            Assert.That(signing, Is.EqualTo(new[] { "v2", "v1" }));
        });
    }

    [Test]
    public async Task VaultIsAskedOncePerRefreshInterval_AndEachVersionIsReadOnce()
    {
        _vault.Add("v1", _time.GetUtcNow().AddDays(-30));

        await _provider.GetSigningCredentialsAsync();
        await _provider.GetSigningCredentialsAsync();

        _time.Advance(TimeSpan.FromMinutes(6));
        await _provider.GetSigningCredentialsAsync();

        Assert.Multiple(() =>
        {
            Assert.That(_vault.Listings, Is.EqualTo(2));
            Assert.That(_vault.KeyReads, Is.EqualTo(1));
        });
    }

    [Test]
    public async Task UnreachableVault_KeepsThePreviousKeysInUse()
    {
        _vault.Add("v1", _time.GetUtcNow().AddDays(-30));
        await _provider.GetSigningCredentialsAsync();

        _vault.Unreachable = true;
        _time.Advance(TimeSpan.FromMinutes(6));

        var stale = await KeyIdsAsync();
        var listingsAfterFailure = _vault.Listings;
        await KeyIdsAsync();

        Assert.Multiple(() =>
        {
            Assert.That(stale, Is.EqualTo(new[] { "v1" }));
            Assert.That(_vault.Listings, Is.EqualTo(listingsAfterFailure), "A failed refresh is not retried on every call.");
        });
    }

    [Test]
    public void UnreachableVault_OnTheFirstRead_Fails()
    {
        _vault.Unreachable = true;

        Assert.That(async () => await _provider.GetSigningCredentialsAsync(), Throws.InstanceOf<Azure.RequestFailedException>());
    }

    [Test]
    public void KeyWithNoUsableVersion_Fails()
    {
        _vault.Add("disabled", _time.GetUtcNow().AddDays(-30)).Enabled = false;

        Assert.That(async () => await _provider.GetSigningCredentialsAsync(), Throws.InvalidOperationException);
    }

    private async Task<string[]> KeyIdsAsync()
        => [.. (await _provider.GetSigningCredentialsAsync()).Select(credential => credential.Key.KeyId)];

    private static string CreateToken(SigningCredentials credentials)
        => new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "https://issuer.test",
            Audience = "audience",
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = credentials
        });
}
