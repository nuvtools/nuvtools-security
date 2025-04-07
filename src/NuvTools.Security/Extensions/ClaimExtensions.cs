using System.Reflection;
using System.Security.Claims;
using ClaimTypes = NuvTools.Security.Models.ClaimTypes;

namespace NuvTools.Security.Extensions;
public static class ClaimExtensions
{
    public static void AddPermission(this List<Claim> claims, string value)
    {
        claims.Add(new Claim(ClaimTypes.Permission, value));
    }

    public static void AddByClass(this List<Claim> claims, string claimType, Type classType)
    {
        List<Claim> permissions = [.. classType.GetFields(BindingFlags.Public | BindingFlags.Static |
           BindingFlags.FlattenHierarchy)
            .Where(fi => fi.IsLiteral && !fi.IsInitOnly && fi.FieldType == typeof(string))
            .Select(e => new Claim(claimType, (string)e.GetRawConstantValue()!))];

        claims.AddRange(permissions);
    }

    public static void AddPermissionByClass(this List<Claim> claims, Type classType)
    {
        claims.AddByClass(ClaimTypes.Permission, classType);
    }
}