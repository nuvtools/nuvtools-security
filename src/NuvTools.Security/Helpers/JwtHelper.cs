using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace NuvTools.Security.Helpers;

/// <summary>
/// Provides helper methods for generating, parsing, and validating JSON Web Tokens (JWTs).
/// </summary>
public static class JwtHelper
{
    /// <summary>
    /// Generates a signed JWT token.
    /// </summary>
    /// <param name="key">The secret key used for signing the token.</param>
    /// <param name="issuer">The token issuer (usually your API or authentication service).</param>
    /// <param name="audience">The intended audience for the token.</param>
    /// <param name="claims">The claims to include in the token payload.</param>
    /// <param name="expires">The optional expiration date and time for the token.</param>
    /// <returns>A signed JWT as a <see cref="string"/>.</returns>
    public static string Generate(
        string key,
        string issuer,
        string audience,
        IEnumerable<Claim> claims,
        DateTime? expires = null)
    {
        var token = CreateJwtToken(key, issuer, audience, claims, expires);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>
    /// Extracts the <see cref="ClaimsPrincipal"/> from an expired JWT without validating its expiration.
    /// </summary>
    /// <param name="token">The expired JWT.</param>
    /// <param name="key">The signing key used to validate the token signature.</param>
    /// <returns>A <see cref="ClaimsPrincipal"/> representing the token subject.</returns>
    /// <exception cref="SecurityTokenException">Thrown if the token signature or algorithm is invalid.</exception>
    public static ClaimsPrincipal GetPrincipalFromExpiredToken(string token, string key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        var parameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = GetSymmetricSecurityKey(key),
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            RoleClaimType = ClaimTypes.Role,
            ClockSkew = TimeSpan.Zero
        };

        var handler = new JwtSecurityTokenHandler();
        var principal = handler.ValidateToken(token, parameters, out var securityToken);

        if (securityToken is not JwtSecurityToken jwtToken ||
            !string.Equals(jwtToken.Header.Alg, SecurityAlgorithms.HmacSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new SecurityTokenException("Invalid token or signature algorithm.");
        }

        return principal;
    }

    /// <summary>
    /// Generates a secure random refresh token as a Base64 string.
    /// </summary>
    public static string GenerateRefreshToken()
    {
        Span<byte> randomBytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(randomBytes);
        return Convert.ToBase64String(randomBytes);
    }

    /// <summary>
    /// Parses claims directly from a JWT string without signature validation.
    /// </summary>
    /// <param name="jwt">The JWT string.</param>
    /// <returns>A list of <see cref="Claim"/> parsed from the token payload.</returns>
    public static IReadOnlyList<Claim> ParseClaimsFromJwt(string jwt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jwt);

        var payload = GetJwtPayload(jwt);
        var keyValuePairs = DeserializePayload(payload);

        var claims = new List<Claim>();

        if (keyValuePairs.TryGetValue("roles", out var rolesElement))
        {
            claims.AddRange(ExtractRoleClaims(rolesElement));
            keyValuePairs.Remove("roles");
        }

        foreach (var (key, value) in keyValuePairs)
        {
            var claimValue = value.ValueKind == JsonValueKind.String
                ? value.GetString() ?? string.Empty
                : value.ToString();

            claims.Add(new Claim(key, claimValue));
        }

        return claims;
    }

    /// <summary>
    /// Determines whether a JWT has expired based on its "exp" claim.
    /// </summary>
    public static bool IsTokenExpired(string jwt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jwt);

        var payload = GetJwtPayload(jwt);
        var keyValuePairs = DeserializePayload(payload);

        if (!keyValuePairs.TryGetValue("exp", out var expElement))
            throw new KeyNotFoundException("The JWT does not contain an 'exp' (expiration) claim.");

        var exp = expElement.GetInt64();
        return DateTimeOffset.FromUnixTimeSeconds(exp) <= DateTimeOffset.UtcNow;
    }

    private static SymmetricSecurityKey GetSymmetricSecurityKey(string key) =>
        new(Encoding.UTF8.GetBytes(key));

    private static JwtSecurityToken CreateJwtToken(
        string key,
        string issuer,
        string audience,
        IEnumerable<Claim> claims,
        DateTime? expires)
    {
        var credentials = new SigningCredentials(GetSymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

        return new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            expires: expires,
            signingCredentials: credentials);
    }

    private static string GetJwtPayload(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length < 2)
            throw new FormatException("Invalid JWT format. Expected at least two segments.");

        return parts[1];
    }

    private static Dictionary<string, JsonElement> DeserializePayload(string payload)
    {
        var jsonBytes = ParseBase64WithoutPadding(payload);

        return JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(jsonBytes)
            ?? throw new InvalidOperationException("Failed to parse JWT payload.");
    }

    /// <summary>
    /// Decodes a Base64Url-encoded string, adding padding if necessary.
    /// </summary>
    private static byte[] ParseBase64WithoutPadding(string base64)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(base64);

        // JWT uses Base64Url encoding, replace URL-safe chars
        string normalized = base64
            .Replace('-', '+')
            .Replace('_', '/');

        // Add missing padding if needed
        int padding = normalized.Length % 4;
        if (padding > 0)
            normalized = normalized.PadRight(normalized.Length + (4 - padding), '=');

        return Convert.FromBase64String(normalized);
    }


    private static IEnumerable<Claim> ExtractRoleClaims(JsonElement rolesElement)
    {
        if (rolesElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var role in rolesElement.EnumerateArray())
            {
                var roleName = role.GetString();
                if (!string.IsNullOrWhiteSpace(roleName))
                    yield return new Claim(ClaimTypes.Role, roleName);
            }
        }
        else if (rolesElement.ValueKind == JsonValueKind.String)
        {
            var roleName = rolesElement.GetString();
            if (!string.IsNullOrWhiteSpace(roleName))
                yield return new Claim(ClaimTypes.Role, roleName);
        }
    }
}
