using System.Security.Cryptography;
using System.Text;

namespace NuvTools.Security.Helpers;

/// <summary>
/// Provides helper methods for computing cryptographic hashes.
/// </summary>
public static class CryptographyHelper
{
    /// <summary>
    /// Supported hashing algorithms.
    /// </summary>
    public enum HashAlgorithmType
    {
        SHA256,
        SHA512
    }

    /// <summary>
    /// Computes the cryptographic hash of a string using the specified algorithm.
    /// </summary>
    /// <param name="value">The input string to be hashed. If null or empty, an empty string is returned.</param>
    /// <param name="algorithm">The hash algorithm to use. Defaults to SHA256.</param>
    /// <returns>
    /// A lowercase hexadecimal representation of the computed hash.
    /// </returns>
    public static string ComputeHash(string? value, HashAlgorithmType algorithm = HashAlgorithmType.SHA256)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        byte[] bytes = Encoding.UTF8.GetBytes(value);
        byte[] hashBytes = algorithm switch
        {
            HashAlgorithmType.SHA512 => SHA512.HashData(bytes),
            _ => SHA256.HashData(bytes)
        };

        StringBuilder builder = new(hashBytes.Length * 2);
        foreach (byte b in hashBytes)
        {
            builder.Append(b.ToString("x2"));
        }

        return builder.ToString();
    }

    /// <summary>
    /// Computes a SHA-256 hash for the given string.
    /// </summary>
    public static string ComputeSHA256Hash(string? value) => ComputeHash(value, HashAlgorithmType.SHA256);

    /// <summary>
    /// Computes a SHA-512 hash for the given string.
    /// </summary>
    public static string ComputeSHA512Hash(string? value) => ComputeHash(value, HashAlgorithmType.SHA512);
}
