using System.Security.Cryptography;
using System.Text;

namespace NuvTools.Security.Helpers;

public class CryptographyHelper
{
    /// <summary>
    /// Will return a 64-character string (32 bytes represented in hex).
    /// </summary>
    /// <param name="value">The input string to be hashed. If null or empty, an empty string is returned.</param>
    /// <returns>A 64-character lowercase hexadecimal representation of the SHA-256 hash of the input string.</returns>

    public static string ComputeSHA256Hash(string value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;

        byte[] bytes = Encoding.UTF8.GetBytes(value);

        byte[] hashBytes = SHA256.HashData(bytes);

        StringBuilder builder = new();
        foreach (byte b in hashBytes)
        {
            builder.Append(b.ToString("x2"));
        }

        return builder.ToString();
    }
}
