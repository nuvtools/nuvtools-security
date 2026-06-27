using NUnit.Framework;
using NuvTools.Security.Helpers;
using static NuvTools.Security.Helpers.AesEncryptionHelper;

namespace NuvTools.Security.Test;

[TestFixture]
public class AesEncryptionHelperTests
{
    private const string Key = "super-secret-key";

    [TestCase(SymmetricAlgorithmType.AES128)]
    [TestCase(SymmetricAlgorithmType.AES192)]
    [TestCase(SymmetricAlgorithmType.AES256)]
    public void EncryptToString_ThenDecryptToString_ShouldRoundTrip(SymmetricAlgorithmType algorithm)
    {
        // Arrange
        const string plainText = "Sensitive value 1234 áéíóú";

        // Act
        string cipher = AesEncryptionHelper.EncryptToString(plainText, Key, algorithm);
        string decrypted = AesEncryptionHelper.DecryptToString(cipher, Key, algorithm);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.That(cipher, Is.Not.EqualTo(plainText));
            Assert.That(decrypted, Is.EqualTo(plainText));
        });
    }

    [TestCase(SymmetricAlgorithmType.AES128)]
    [TestCase(SymmetricAlgorithmType.AES192)]
    [TestCase(SymmetricAlgorithmType.AES256)]
    public void EncryptToBytes_ThenDecryptToString_ShouldRoundTrip(SymmetricAlgorithmType algorithm)
    {
        // Arrange
        const string plainText = "byte round trip";

        // Act
        byte[] cipher = AesEncryptionHelper.EncryptToBytes(plainText, Key, algorithm);
        string decrypted = AesEncryptionHelper.DecryptToString(cipher, Key, algorithm);

        // Assert
        Assert.That(decrypted, Is.EqualTo(plainText));
    }

    [TestCase(null)]
    [TestCase("")]
    public void EncryptToBytes_ShouldReturnEmpty_ForNullOrEmptyInput(string? input)
    {
        // Act
        byte[] result = AesEncryptionHelper.EncryptToBytes(input!, Key);

        // Assert
        Assert.That(result, Is.Empty);
    }

    [TestCase(null)]
    [TestCase("")]
    public void DecryptToString_ShouldReturnEmpty_ForNullOrEmptyInput(string? input)
    {
        // Act
        string result = AesEncryptionHelper.DecryptToString(input!, Key);

        // Assert
        Assert.That(result, Is.Empty);
    }

    [Test]
    public void DecryptToString_ShouldReturnInputAsIs_ForNonBase64LegacyData()
    {
        // Arrange (plain legacy value that was never encrypted)
        const string legacy = "12345678900";

        // Act
        string result = AesEncryptionHelper.DecryptToString(legacy, Key);

        // Assert
        Assert.That(result, Is.EqualTo(legacy));
    }

    [Test]
    public void EncryptToBytes_ShouldPrefixIv_AndVaryAcrossCalls()
    {
        // Arrange
        const string plainText = "same input";

        // Act
        byte[] first = AesEncryptionHelper.EncryptToBytes(plainText, Key);
        byte[] second = AesEncryptionHelper.EncryptToBytes(plainText, Key);

        // Assert
        Assert.Multiple(() =>
        {
            // IV (16 bytes) + at least one block of ciphertext
            Assert.That(first.Length, Is.GreaterThan(16));
            // Random IV => different ciphertext for identical plaintext
            Assert.That(first, Is.Not.EqualTo(second));
        });
    }

    [Test]
    public void DecryptToString_FromBytes_ShouldThrow_ForMalformedPayload()
    {
        // Arrange (too short to contain IV + ciphertext)
        byte[] malformed = [1, 2, 3];

        // Act / Assert
        Assert.Throws<ArgumentOutOfRangeException>(
            () => AesEncryptionHelper.DecryptToString(malformed, Key));
    }
}
