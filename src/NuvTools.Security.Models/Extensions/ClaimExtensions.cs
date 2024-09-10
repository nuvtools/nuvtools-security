using System.Reflection;
using System.Security.Claims;

namespace NuvTools.Security.Models.Extensions;
public static class ClaimExtensions
{
    public static void AddPermission(this List<Claim> claims, string value)
    {
        claims.Add(new Claim(ClaimTypes.Permission, value));
    }

    public static void AddByClass(this List<Claim> claims, string claimType, Type classType)
    {
        var permissions = classType.GetFields(BindingFlags.Public | BindingFlags.Static |
           BindingFlags.FlattenHierarchy)
            .Where(fi => fi.IsLiteral && !fi.IsInitOnly && fi.FieldType == typeof(string))
            .Select(e => new Claim(claimType, (string)e.GetRawConstantValue()!))
            .ToList();

        claims.AddRange(permissions);
    }

    public static void AddPermissionByClass(this List<Claim> claims, Type classType)
    {
        claims.AddByClass(ClaimTypes.Permission, classType);
    }
}