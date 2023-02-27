using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace NuvTools.Security.Util;

public static class ClaimHelper
{
    public static string Generate(string key, string issuer, string audience, IEnumerable<Claim> claims, DateTime? expires)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));

        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);

        var secToken = new JwtSecurityToken(
                        issuer: issuer,
                        audience: audience,
                        claims: claims,
                    expires: expires,
                    signingCredentials: credentials);

        var handler = new JwtSecurityTokenHandler();

        return handler.WriteToken(secToken);
    }
}