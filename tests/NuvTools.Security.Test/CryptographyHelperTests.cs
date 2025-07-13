using NUnit.Framework;
using NuvTools.Security.Helpers;

namespace NuvTools.Security.Test;

[TestFixture]
public class CryptographyHelperTests
{
    [Test]
    public void ComputeSHA256Hash_ShouldReturnCorrectHash_ForKnownInput()
    {
        string input = "hello world";
        string expectedHash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

        string result = CryptographyHelper.ComputeSHA256Hash(input);

        Assert.That(result, Is.EqualTo(expectedHash));
    }

    [Test]
    public void ComputeSHA256Hash_ShouldReturnEmpty_ForNullInput()
    {
        string? input = string.Empty;

        string result = CryptographyHelper.ComputeSHA256Hash(input);

        Assert.That(result, Is.Empty);
    }

    [Test]
    public void ComputeSHA256Hash_ShouldReturnEmpty_ForEmptyInput()
    {
        string input = "";

        string result = CryptographyHelper.ComputeSHA256Hash(input);

        Assert.That(result, Is.Empty);
    }

    [Test]
    public void ComputeSHA256Hash_ShouldReturn64CharHex_ForValidInput()
    {
        string input = "test";

        string result = CryptographyHelper.ComputeSHA256Hash(input);

        Assert.That(result.Length, Is.EqualTo(64));
        Assert.That(result, Does.Match("^[a-f0-9]{64}$")); // hexadecimal lowercase
    }
}
