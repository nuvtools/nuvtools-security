using Microsoft.IdentityModel.Tokens;
using NUnit.Framework;
using NuvTools.Security.Helpers;
using System.Security.Claims;
using System.Text.Json;

namespace NuvTools.Security.Test;

[TestFixture]
public class JwtHelperTests
{
    private const string SecretKey = "super_secret_key_12345!@#_ThisKeyMustBeAtLeast32BytesLong";
    private const string Issuer = "NuvTools.Security.Tests";
    private const string Audience = "NuvTools.Client";

    private List<Claim> _testClaims = null!;

    [SetUp]
    public void SetUp()
    {
        _testClaims =
        [
            new Claim(ClaimTypes.NameIdentifier, "user123"),
            new Claim(ClaimTypes.Email, "user@example.com"),
            new Claim(ClaimTypes.Role, "Admin")
        ];
    }

    [Test]
    public void Generate_ShouldReturn_ValidJwtString()
    {
        // Act
        var token = JwtHelper.Generate(SecretKey, Issuer, Audience, _testClaims, DateTime.UtcNow.AddMinutes(10));

        // Assert
        Assert.Multiple(() =>
        {
            Assert.That(token, Is.Not.Null.And.Not.Empty);
            Assert.That(token.Split('.').Length, Is.EqualTo(3), "JWT should have 3 segments");
        });
    }

    [Test]
    public void GenerateRefreshToken_ShouldReturn_Base64String()
    {
        // Act
        var refreshToken = JwtHelper.GenerateRefreshToken();

        // Assert
        Assert.Multiple(() =>
        {
            Assert.That(refreshToken, Is.Not.Null.And.Not.Empty);
            Assert.That(() => Convert.FromBase64String(refreshToken), Throws.Nothing, "Should be valid Base64");
        });
    }

    [Test]
    public void ParseClaimsFromJwt_ShouldReturn_AllClaims()
    {
        // Arrange
        var jwt = JwtHelper.Generate(SecretKey, Issuer, Audience, _testClaims, DateTime.UtcNow.AddMinutes(5));

        // Act
        var claims = JwtHelper.ParseClaimsFromJwt(jwt);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.That(claims, Is.Not.Null);
            Assert.That(claims.Count, Is.GreaterThanOrEqualTo(3));
            Assert.That(claims.Any(c => c.Type == ClaimTypes.Email && c.Value == "user@example.com"));
            Assert.That(claims.Any(c => c.Type == ClaimTypes.Role && c.Value == "Admin"));
        });
    }

    [Test]
    public void IsTokenExpired_ShouldReturnFalse_ForActiveToken()
    {
        // Arrange
        var jwt = JwtHelper.Generate(SecretKey, Issuer, Audience, _testClaims, DateTime.UtcNow.AddMinutes(5));

        // Act
        var isExpired = JwtHelper.IsTokenExpired(jwt);

        // Assert
        Assert.That(isExpired, Is.False);
    }

    [Test]
    public void IsTokenExpired_ShouldReturnTrue_ForExpiredToken()
    {
        // Arrange
        var jwt = JwtHelper.Generate(SecretKey, Issuer, Audience, _testClaims, DateTime.UtcNow.AddMinutes(-5));

        // Act
        var isExpired = JwtHelper.IsTokenExpired(jwt);

        // Assert
        Assert.That(isExpired, Is.True);
    }

    [Test]
    public void GetPrincipalFromExpiredToken_ShouldReturnPrincipal_WhenTokenIsExpired()
    {
        // Arrange
        var jwt = JwtHelper.Generate(SecretKey, Issuer, Audience, _testClaims, DateTime.UtcNow.AddMinutes(-1));

        // Act
        var principal = JwtHelper.GetPrincipalFromExpiredToken(jwt, SecretKey);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.That(principal, Is.Not.Null);
            Assert.That(principal.Identity?.IsAuthenticated, Is.True);
            Assert.That(principal.Claims.Any(c => c.Type == ClaimTypes.Email && c.Value == "user@example.com"));
        });
    }

    [Test]
    public void GetPrincipalFromExpiredToken_ShouldThrow_WhenInvalidKey()
    {
        // Arrange
        var jwt = JwtHelper.Generate(SecretKey, Issuer, Audience, _testClaims, DateTime.UtcNow.AddMinutes(-1));

        // Act & Assert
        Assert.That(() => JwtHelper.GetPrincipalFromExpiredToken(jwt, "invalid_key"),
            Throws.InstanceOf<SecurityTokenException>());
    }


    [Test]
    public void ParseClaimsFromJwt_ShouldThrow_WhenInvalidJwt()
    {
        // Act & Assert
        Assert.That(
            () => JwtHelper.ParseClaimsFromJwt("invalid.jwt.token"),
            Throws.TypeOf<JsonException>()
        );
    }


    [Test]
    public void IsTokenExpired_ShouldReturnTrue_WhenInvalidJwt()
    {
        // Act & Assert
        Assert.That(
            () => JwtHelper.IsTokenExpired("invalid.jwt.token"),
            Throws.TypeOf<JsonException>()
        );

        var token = JwtHelper.Generate(SecretKey, Issuer, Audience, _testClaims, DateTime.UtcNow.AddMinutes(-1));

        var expired = JwtHelper.IsTokenExpired(token);

        // Assert
        Assert.That(expired, Is.True);
    }
}