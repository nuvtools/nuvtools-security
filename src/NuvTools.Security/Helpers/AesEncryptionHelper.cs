using System.Security.Cryptography;
using System.Text;

namespace NuvTools.Security.Helpers;

/// <summary>
/// Provides helper methods for AES symmetric encryption and decryption.
/// The encryption format is AES-CBC with the layout IV (16 bytes) + ciphertext,
/// using a SHA-256-derived key.
/// </summary>
public static class AesEncryptionHelper
{
    /// <summary>
    /// Supported symmetric encryption algorithms. The enum value equals the key size in bits.
    /// </summary>
    public enum SymmetricAlgorithmType
    {
        AES128 = 128,
        AES192 = 192,
        AES256 = 256
    }

    /// <summary>
    /// Encrypts a string and returns the result as a byte array.
    /// Format: IV (16 bytes) + ciphertext.
    /// </summary>
    public static byte[] EncryptToBytes(string plainText, string key, SymmetricAlgorithmType algorithm = SymmetricAlgorithmType.AES256)
    {
        if (string.IsNullOrEmpty(plainText))
            return [];

        using var aes = Aes.Create();
        aes.Key = DeriveKey(key, algorithm);
        aes.GenerateIV();

        using var encryptor = aes.CreateEncryptor();
        var plainBytes = Encoding.UTF8.GetBytes(plainText);
        var cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

        // IV (16 bytes) + CipherText
        var result = new byte[aes.IV.Length + cipherBytes.Length];
        aes.IV.CopyTo(result, 0);
        cipherBytes.CopyTo(result, aes.IV.Length);

        return result;
    }

    /// <summary>
    /// Decrypts a byte array and returns the original plain bytes (without UTF-8 conversion).
    /// </summary>
    public static byte[] DecryptToBytes(byte[] cipherData, string key, SymmetricAlgorithmType algorithm = SymmetricAlgorithmType.AES256)
    {
        if (cipherData is null || cipherData.Length == 0)
            return [];

        using var aes = Aes.Create();
        aes.Key = DeriveKey(key, algorithm);

        var iv = cipherData[..16];
        var cipherBytes = cipherData[16..];

        aes.IV = iv;
        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
    }

    /// <summary>
    /// Decrypts a Base64 string and returns the original plain bytes (without UTF-8 conversion).
    /// </summary>
    public static byte[] DecryptToBytes(string cipherText, string key, SymmetricAlgorithmType algorithm = SymmetricAlgorithmType.AES256)
        => string.IsNullOrEmpty(cipherText)
            ? []
            : DecryptToBytes(Convert.FromBase64String(cipherText), key, algorithm);


    /// <summary>
    /// Encrypts a string and returns the result as a Base64 string.
    /// </summary>
    public static string EncryptToString(string plainText, string key, SymmetricAlgorithmType algorithm = SymmetricAlgorithmType.AES256)
        => Convert.ToBase64String(EncryptToBytes(plainText, key, algorithm));

    /// <summary>
    /// Decrypts a Base64 string and returns the original plain text.
    /// If the input is not a valid Base64 string or cannot be decrypted,
    /// the value is returned as-is (fallback for legacy plain-text data).
    /// </summary>
    public static string DecryptToString(string cipherText, string key, SymmetricAlgorithmType algorithm = SymmetricAlgorithmType.AES256)
    {
        if (string.IsNullOrEmpty(cipherText))
            return string.Empty;

        byte[] cipherData;
        try
        {
            cipherData = Convert.FromBase64String(cipherText);
        }
        catch (FormatException)
        {
            return cipherText;
        }

        // Must have at least IV (16 bytes) + 1 byte of ciphertext
        if (cipherData.Length < 17)
            return cipherText;

        try
        {
            return DecryptToString(cipherData, key, algorithm);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentOutOfRangeException)
        {
            return cipherText;
        }
    }

    /// <summary>
    /// Decrypts a byte array and returns the original plain text.
    /// Throws if the payload is malformed (caller is responsible for validation
    /// or fallback handling).
    /// </summary>
    public static string DecryptToString(byte[] cipherData, string key, SymmetricAlgorithmType algorithm = SymmetricAlgorithmType.AES256)
    {
        if (cipherData is null || cipherData.Length == 0)
            return string.Empty;

        if (cipherData.Length < 17)
            throw new ArgumentOutOfRangeException(nameof(cipherData), "Cipher data must contain at least IV (16 bytes) + 1 byte of ciphertext.");

        using var aes = Aes.Create();
        aes.Key = DeriveKey(key, algorithm);

        var iv = cipherData[..16];
        var cipherBytes = cipherData[16..];

        aes.IV = iv;
        using var decryptor = aes.CreateDecryptor();
        var plainBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);

        return Encoding.UTF8.GetString(plainBytes);
    }

    /// <summary>
    /// Encrypts a string using AES-128 and returns the result as a byte array.
    /// </summary>
    public static byte[] EncryptAES128(string plainText, string key) => EncryptToBytes(plainText, key, SymmetricAlgorithmType.AES128);

    /// <summary>
    /// Encrypts a string using AES-192 and returns the result as a byte array.
    /// </summary>
    public static byte[] EncryptAES192(string plainText, string key) => EncryptToBytes(plainText, key, SymmetricAlgorithmType.AES192);

    /// <summary>
    /// Encrypts a string using AES-256 and returns the result as a byte array.
    /// </summary>
    public static byte[] EncryptAES256(string plainText, string key) => EncryptToBytes(plainText, key, SymmetricAlgorithmType.AES256);

    /// <summary>
    /// Decrypts a byte array encrypted with AES-128 and returns the original plain text.
    /// </summary>
    public static string DecryptAES128(byte[] cipherData, string key) => DecryptToString(cipherData, key, SymmetricAlgorithmType.AES128);

    /// <summary>
    /// Decrypts a byte array encrypted with AES-192 and returns the original plain text.
    /// </summary>
    public static string DecryptAES192(byte[] cipherData, string key) => DecryptToString(cipherData, key, SymmetricAlgorithmType.AES192);

    /// <summary>
    /// Decrypts a byte array encrypted with AES-256 and returns the original plain text.
    /// </summary>
    public static string DecryptAES256(byte[] cipherData, string key) => DecryptToString(cipherData, key, SymmetricAlgorithmType.AES256);

    private static byte[] DeriveKey(string key, SymmetricAlgorithmType algorithm)
    {
        var keySize = (int)algorithm / 8;
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(key));

        if (keySize == hash.Length)
            return hash;

        var derived = new byte[keySize];
        Array.Copy(hash, derived, keySize);
        return derived;
    }
}
