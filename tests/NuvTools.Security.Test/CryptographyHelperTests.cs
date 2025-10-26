using NUnit.Framework;
using NuvTools.Security.Helpers;

namespace NuvTools.Security.Test;

[TestFixture]
public class CryptographyHelperTests
{
    [Test]
    public void ComputeSHA256Hash_ShouldReturnCorrectHash_ForKnownInput()
    {
        // Arrange
        string input = "hello world";
        const string expectedHash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

        // Act
        string result = CryptographyHelper.ComputeSHA256Hash(input);

        // Assert
        Assert.That(result, Is.EqualTo(expectedHash));
    }

    [Test]
    public void ComputeSHA512Hash_ShouldReturnCorrectHash_ForKnownInput()
    {
        // Arrange
        string input = "hello world";
        const string expectedHash =
            "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f" +
            "989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f";

        // Act
        string result = CryptographyHelper.ComputeSHA512Hash(input);

        // Assert
        Assert.That(result, Is.EqualTo(expectedHash));
    }

    [Test]
    public void ComputeHash_ShouldUseSHA256ByDefault()
    {
        // Arrange
        string input = "test";

        // Act
        string hashDefault = CryptographyHelper.ComputeHash(input);
        string hashExplicit = CryptographyHelper.ComputeSHA256Hash(input);

        // Assert
        Assert.That(hashDefault, Is.EqualTo(hashExplicit));
    }

    [TestCase(null)]
    [TestCase("")]
    public void ComputeSHA256Hash_ShouldReturnEmpty_ForNullOrEmptyInput(string? input)
    {
        // Act
        string result = CryptographyHelper.ComputeSHA256Hash(input);

        // Assert
        Assert.That(result, Is.Empty);
    }

    [TestCase("test", 64)]
    [TestCase("another", 64)]
    public void ComputeSHA256Hash_ShouldReturn64CharHex_ForValidInput(string input, int expectedLength)
    {
        // Act
        string result = CryptographyHelper.ComputeSHA256Hash(input);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.That(result.Length, Is.EqualTo(expectedLength));
            Assert.That(result, Does.Match("^[a-f0-9]{64}$")); // lowercase hexadecimal
        });
    }

    [TestCase("test", 128)]
    [TestCase("123", 128)]
    public void ComputeSHA512Hash_ShouldReturn128CharHex_ForValidInput(string input, int expectedLength)
    {
        // Act
        string result = CryptographyHelper.ComputeSHA512Hash(input);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.That(result.Length, Is.EqualTo(expectedLength));
            Assert.That(result, Does.Match("^[a-f0-9]{128}$"));
        });
    }

    [Test]
    public void ComputeHash_ShouldBeConsistent_ForSameInput()
    {
        // Arrange
        string input = "consistent";

        // Act
        string first = CryptographyHelper.ComputeSHA256Hash(input);
        string second = CryptographyHelper.ComputeSHA256Hash(input);

        // Assert
        Assert.That(first, Is.EqualTo(second));
    }

    [Test]
    public void ComputeHash_ShouldBeDifferent_ForDifferentAlgorithms()
    {
        // Arrange
        string input = "sameInput";

        // Act
        string hash256 = CryptographyHelper.ComputeSHA256Hash(input);
        string hash512 = CryptographyHelper.ComputeSHA512Hash(input);

        // Assert
        Assert.That(hash256, Is.Not.EqualTo(hash512));
    }
}