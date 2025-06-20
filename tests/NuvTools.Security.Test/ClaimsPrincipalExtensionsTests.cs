using NUnit.Framework;
using NUnit.Framework.Legacy;
using NuvTools.Security.Extensions;
using System;
using System.Security.Claims;

namespace NuvTools.Security.Test;

[TestFixture]
public class ClaimsPrincipalExtensionsTests
{
    private ClaimsPrincipal CreatePrincipal(params Claim[] claims)
    {
        var identity = new ClaimsIdentity(claims, "TestAuthType");
        return new ClaimsPrincipal(identity);
    }

    [Test]
    public void GetId_ShouldReturnNameIdentifier()
    {
        var user = CreatePrincipal(new Claim(ClaimTypes.NameIdentifier, "123"));

        var id = user.GetId();

        Assert.That(id, Is.EqualTo("123"));
    }

    [Test]
    public void GetId_ShouldReturnSubIfNameIdentifierNotPresent()
    {
        var user = CreatePrincipal(new Claim("sub", "456"));

        var id = user.GetId();

        Assert.That(id, Is.EqualTo("456"));
    }

    [Test]
    public void GetId_ShouldThrowIfNoValidClaim()
    {
        var user = CreatePrincipal();

        Assert.Throws<InvalidOperationException>(() => user.GetId());
    }

    [Test]
    public void GetName_ShouldReturnClaimTypesName()
    {
        var user = CreatePrincipal(new Claim(ClaimTypes.Name, "Alice"));

        var name = user.GetName();

        Assert.That(name, Is.EqualTo("Alice"));
    }

    [Test]
    public void GetName_ShouldReturnFallbackNameClaim()
    {
        var user = CreatePrincipal(new Claim("name", "Bob"));

        var name = user.GetName();

        Assert.That(name, Is.EqualTo("Bob"));
    }

    [Test]
    public void GetSurname_ShouldReturnClaimTypesSurname()
    {
        var user = CreatePrincipal(new Claim(ClaimTypes.Surname, "Smith"));

        var surname = user.GetSurname();

        Assert.That(surname, Is.EqualTo("Smith"));
    }

    [Test]
    public void GetSurname_ShouldReturnFallbackFamilyName()
    {
        var user = CreatePrincipal(new Claim("family_name", "Johnson"));

        var surname = user.GetSurname();

        Assert.That(surname, Is.EqualTo("Johnson"));
    }

    [Test]
    public void GetEmail_ShouldReturnClaimTypesEmail()
    {
        var user = CreatePrincipal(new Claim(ClaimTypes.Email, "test@example.com"));

        var email = user.GetEmail();

        Assert.That(email, Is.EqualTo("test@example.com"));
    }

    [Test]
    public void GetEmail_ShouldReturnFallbackValidEmail()
    {
        var user = CreatePrincipal(new Claim("upn", "user@domain.com"));

        var email = user.GetEmail();

        Assert.That(email, Is.EqualTo("user@domain.com"));
    }

    [Test]
    public void HasValue_ShouldReturnTrueWhenValueExists()
    {
        var user = CreatePrincipal(new Claim("extension_roles", "Admin,User"));

        var result = user.HasValue("roles", "Admin");

        Assert.That(result, Is.True);
    }

    [Test]
    public void HasValue_ShouldReturnFalseWhenValueDoesNotExist()
    {
        var user = CreatePrincipal(new Claim("extension_roles", "Admin,User"));

        var result = user.HasValue("roles", "Manager");

        Assert.That(result, Is.False);
    }

    [Test]
    public void GetCustomAttributeValues_ShouldReturnParsedInts()
    {
        var user = CreatePrincipal(new Claim("extension_ids", "1, 2, 3"));

        var values = user.GetCustomAttributeValues<int>("ids");

        Assert.That(values, Is.EqualTo(new[] { 1, 2, 3 }));
    }

    [Test]
    public void GetCustomAttributeValues_ShouldReturnParsedEnums()
    {
        var user = CreatePrincipal(new Claim("extension_levels", "Low,High"));

        var values = user.GetCustomAttributeValues<TestLevel>("levels");

        Assert.That(values, Is.EqualTo(new[] { TestLevel.Low, TestLevel.High }));
    }

    public enum TestLevel
    {
        Low,
        Medium,
        High
    }
}
