using NUnit.Framework;
using NuvTools.Security.Extensions;
using NuvTools.Security.Models;
using System;
using System.Security.Claims;
using ClaimTypes = System.Security.Claims.ClaimTypes;

namespace NuvTools.Security.Test;

[TestFixture]
public class ClaimsPrincipalExtensionsTests
{
    private static ClaimsPrincipal CreatePrincipal(params Claim[] claims)
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
        var user = CreatePrincipal(new Claim(ClaimConstants.Sub, "456"));

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
    public void GetSub_ShouldReturnSubClaim()
    {
        var user = CreatePrincipal(new Claim(ClaimConstants.Sub, "999"));

        var sub = user.GetSub();

        Assert.That(sub, Is.EqualTo("999"));
    }

    [Test]
    public void GetNameIdentifier_ShouldReturnNameIdentifierClaim()
    {
        var user = CreatePrincipal(new Claim(ClaimTypes.NameIdentifier, "abc"));

        var result = user.GetNameIdentifier();

        Assert.That(result, Is.EqualTo("abc"));
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
    public void GetGivenName_ShouldReturnGivenNameClaim()
    {
        var user = CreatePrincipal(new Claim(ClaimConstants.GivenName, "Charlie"));

        var givenName = user.GetGivenName();

        Assert.That(givenName, Is.EqualTo("Charlie"));
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
        var user = CreatePrincipal(new Claim(ClaimConstants.FamilyName, "Johnson"));

        var surname = user.GetFamilyName();

        Assert.That(surname, Is.EqualTo("Johnson"));
    }

    [Test]
    public void GetFamilyName_ShouldReturnFamilyNameClaim()
    {
        var user = CreatePrincipal(new Claim(ClaimConstants.FamilyName, "Doe"));

        var familyName = user.GetFamilyName();

        Assert.That(familyName, Is.EqualTo("Doe"));
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
        var user = CreatePrincipal(new Claim(ClaimConstants.Upn, "user@domain.com"));

        var email = user.GetEmail();

        Assert.That(email, Is.EqualTo("user@domain.com"));
    }

    [Test]
    public void GetUpn_ShouldReturnUpnClaim()
    {
        var user = CreatePrincipal(new Claim(ClaimConstants.Upn, "upn@domain.com"));

        var upn = user.GetUpn();

        Assert.That(upn, Is.EqualTo("upn@domain.com"));
    }

    [Test]
    public void GetPreferredUsername_ShouldReturnPreferredUsernameClaim()
    {
        var user = CreatePrincipal(new Claim(ClaimConstants.PreferredUsername, "prefuser"));

        var result = user.GetPreferredUsername();

        Assert.That(result, Is.EqualTo("prefuser"));
    }

    [Test]
    public void GetUniqueName_ShouldReturnUniqueNameClaim()
    {
        var user = CreatePrincipal(new Claim(ClaimConstants.UniqueName, "uniqueuser"));

        var result = user.GetUniqueName();

        Assert.That(result, Is.EqualTo("uniqueuser"));
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
      
        int[] expected = [1, 2, 3];
        
        Assert.That(values, Is.EqualTo(expected));
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
