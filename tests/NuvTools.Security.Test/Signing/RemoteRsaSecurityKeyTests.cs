using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NuvTools.Security.Signing;
using NUnit.Framework;
using System.Security.Cryptography;

namespace NuvTools.Security.Test.Signing;

[TestFixture]
public class RemoteRsaSecurityKeyTests
{
    private RSA _privateHalf = null!;
    private int _signatures;

    [SetUp]
    public void CreateKey()
    {
        _privateHalf = RSA.Create(2048);
        _signatures = 0;
    }

    [TearDown]
    public void DisposeKey() => _privateHalf.Dispose();

    [Test]
    public async Task Token_IsSignedByTheDelegate_AndValidatesWithThePublicKeyAlone()
    {
        var token = CreateToken(CreateKey("version-1"));

        var result = await ValidateAsync(token, PublicKey("version-1"));

        Assert.Multiple(() =>
        {
            Assert.That(_signatures, Is.EqualTo(1));
            Assert.That(result.IsValid, Is.True, result.Exception?.Message);
            Assert.That(new JsonWebToken(token).Kid, Is.EqualTo("version-1"));
            Assert.That(new JsonWebToken(token).Alg, Is.EqualTo(SecurityAlgorithms.RsaSha256));
        });
    }

    [Test]
    public async Task Token_AlsoValidatesAgainstTheRemoteKeyItself_WithoutAskingForASignature()
    {
        var key = CreateKey("version-1");
        var token = CreateToken(key);

        var result = await ValidateAsync(token, key);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsValid, Is.True, result.Exception?.Message);
            Assert.That(_signatures, Is.EqualTo(1), "Validation must not reach the private half.");
        });
    }

    [Test]
    public async Task Token_SignedBySomeOtherKey_IsRefused()
    {
        var token = CreateToken(CreateKey("version-1"));

        using var other = RSA.Create(2048);
        var result = await ValidateAsync(token, new RsaSecurityKey(other.ExportParameters(false)) { KeyId = "version-1" });

        Assert.That(result.IsValid, Is.False);
    }

    [Test]
    public void Key_HoldsAndPublishesNoPrivateParameter()
    {
        // Built from the full parameters on purpose: the private ones must be dropped.
        var key = new RemoteRsaSecurityKey(_privateHalf.ExportParameters(includePrivateParameters: true), "version-1", Sign);
        var published = JsonWebKeyConverter.ConvertFromRSASecurityKey(key);

        Assert.Multiple(() =>
        {
            Assert.That(key.Parameters.D, Is.Null);
            Assert.That(key.Parameters.P, Is.Null);
            Assert.That(published.D, Is.Null);
            Assert.That(published.N, Is.Not.Empty);
            Assert.That(key.PrivateKeyStatus, Is.EqualTo(PrivateKeyStatus.Exists));
        });
    }

    private RemoteRsaSecurityKey CreateKey(string keyId)
        => new(_privateHalf.ExportParameters(includePrivateParameters: false), keyId, Sign);

    private RsaSecurityKey PublicKey(string keyId)
        => new(_privateHalf.ExportParameters(includePrivateParameters: false)) { KeyId = keyId };

    private byte[] Sign(byte[] data)
    {
        _signatures++;
        return _privateHalf.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    private static string CreateToken(RemoteRsaSecurityKey key)
        => new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "https://issuer.test",
            Audience = "audience",
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = key.ToSigningCredentials()
        });

    private static Task<TokenValidationResult> ValidateAsync(string token, SecurityKey key)
        => new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = "https://issuer.test",
            ValidAudience = "audience",
            IssuerSigningKey = key
        });
}
