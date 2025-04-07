using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace NuvTools.Security.Util;

public static class JwtHelper
{
    public static string Generate(string key, string issuer, string audience, IEnumerable<Claim> claims, DateTime? expires)
    {
        JwtSecurityToken token = CreateJwtToken(key, issuer, audience, claims, expires);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public static ClaimsPrincipal GetPrincipalFromExpiredToken(string token, string key)
    {
        TokenValidationParameters tokenValidationParameters = new()
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = GetSymmetricSecurityKey(key),
            ValidateIssuer = false,
            ValidateAudience = false,
            RoleClaimType = ClaimTypes.Role,
            ClockSkew = TimeSpan.Zero
        };

        JwtSecurityTokenHandler handler = new();
        ClaimsPrincipal principal = handler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);

        if (securityToken is not JwtSecurityToken jwtSecurityToken ||
            !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
        {
            throw new SecurityTokenException("Invalid token");
        }

        return principal;
    }

    public static string GenerateRefreshToken()
    {
        byte[] randomNumber = new byte[32];
        using RandomNumberGenerator rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    public static List<Claim> ParseClaimsFromJwt(string jwt)
    {
        var claims = new List<Claim>();

        var payload = jwt.Split('.')[1];
        var jsonBytes = ParseBase64WithoutPadding(payload);
        var keyValuePairs = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(jsonBytes);

        if (keyValuePairs == null) return claims;

        if (keyValuePairs.TryGetValue("roles", out var rolesElement))
        {
            if (rolesElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var role in rolesElement.EnumerateArray())
                {
                    claims.Add(new Claim(ClaimTypes.Role, role.GetString() ?? string.Empty));
                }
            }
            else if (rolesElement.ValueKind == JsonValueKind.String)
            {
                claims.Add(new Claim(ClaimTypes.Role, rolesElement.GetString() ?? string.Empty));
            }

            keyValuePairs.Remove("roles");
        }

        foreach (var kvp in keyValuePairs)
        {
            var value = kvp.Value.ValueKind switch
            {
                JsonValueKind.String => kvp.Value.GetString() ?? string.Empty,
                _ => kvp.Value.ToString()
            };

            claims.Add(new Claim(kvp.Key, value));
        }

        return claims;
    }

    public static bool IsTokenExpired(string jwt)
    {
        var payload = jwt.Split('.')[1];
        var jsonBytes = ParseBase64WithoutPadding(payload);
        var keyValuePairs = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(jsonBytes);

        if (keyValuePairs == null 
            || !keyValuePairs.TryGetValue("exp", out var expElement))
        {
            return true;
        }

        var exp = expElement.GetInt64();
        var expDate = DateTimeOffset.FromUnixTimeSeconds(exp);
        return expDate <= DateTimeOffset.UtcNow;
    }

    private static SymmetricSecurityKey GetSymmetricSecurityKey(string key)
    {
        return new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
    }

    private static JwtSecurityToken CreateJwtToken(
        string key,
        string issuer,
        string audience,
        IEnumerable<Claim> claims,
        DateTime? expires)
    {
        SigningCredentials credentials = new(GetSymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature);

        return new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            expires: expires,
            signingCredentials: credentials
        );
    }

    private static byte[] ParseBase64WithoutPadding(string base64)
    {
        int padding = 4 - (base64.Length % 4);
        if (padding < 4)
        {
            base64 = base64.PadRight(base64.Length + padding, '=');
        }

        return Convert.FromBase64String(base64);
    }
}