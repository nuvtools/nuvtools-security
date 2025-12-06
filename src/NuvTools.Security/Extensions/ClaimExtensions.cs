using System.Reflection;
using System.Security.Claims;
using ClaimTypes = NuvTools.Security.Models.ClaimTypes;

namespace NuvTools.Security.Extensions;

/// <summary>
/// Provides extension methods for working with collections of <see cref="Claim"/> objects.
/// </summary>
/// <remarks>
/// These extensions simplify the process of adding permission claims and bulk-adding claims
/// from static class constants.
/// </remarks>
public static class ClaimExtensions
{
    /// <summary>
    /// Adds a permission claim to the claims collection.
    /// </summary>
    /// <param name="claims">The list of claims to add to.</param>
    /// <param name="value">The permission value to add.</param>
    /// <remarks>
    /// This is a convenience method that creates a claim with the
    /// <see cref="ClaimTypes.Permission"/> claim type.
    /// </remarks>
    /// <example>
    /// <code>
    /// var claims = new List&lt;Claim&gt;();
    /// claims.AddPermission("users.read");
    /// claims.AddPermission("users.write");
    /// </code>
    /// </example>
    public static void AddPermission(this List<Claim> claims, string value)
    {
        claims.Add(new Claim(ClaimTypes.Permission, value));
    }

    /// <summary>
    /// Adds claims to the collection by reading all public static string constants from a specified class type.
    /// </summary>
    /// <param name="claims">The list of claims to add to.</param>
    /// <param name="claimType">The claim type to assign to all extracted values.</param>
    /// <param name="classType">The type of the class containing the constant values.</param>
    /// <remarks>
    /// This method uses reflection to find all public, static, readonly string fields in the specified class
    /// and creates a claim for each one using the specified claim type. This is useful when you have a
    /// permissions class with multiple permission constant values.
    /// </remarks>
    /// <example>
    /// <code>
    /// public static class UserPermissions
    /// {
    ///     public const string Read = "users.read";
    ///     public const string Write = "users.write";
    ///     public const string Delete = "users.delete";
    /// }
    ///
    /// var claims = new List&lt;Claim&gt;();
    /// claims.AddByClass("permission", typeof(UserPermissions));
    /// // Results in 3 claims with type "permission" and values "users.read", "users.write", "users.delete"
    /// </code>
    /// </example>
    public static void AddByClass(this List<Claim> claims, string claimType, Type classType)
    {
        List<Claim> permissions = [.. classType.GetFields(BindingFlags.Public | BindingFlags.Static |
           BindingFlags.FlattenHierarchy)
            .Where(fi => fi.IsLiteral && !fi.IsInitOnly && fi.FieldType == typeof(string))
            .Select(e => new Claim(claimType, (string)e.GetRawConstantValue()!))];

        claims.AddRange(permissions);
    }

    /// <summary>
    /// Adds permission claims to the collection by reading all public static string constants
    /// from a specified class type.
    /// </summary>
    /// <param name="claims">The list of claims to add to.</param>
    /// <param name="classType">The type of the class containing the permission constant values.</param>
    /// <remarks>
    /// This is a convenience method that calls <see cref="AddByClass"/> with
    /// <see cref="ClaimTypes.Permission"/> as the claim type.
    /// </remarks>
    /// <example>
    /// <code>
    /// public static class UserPermissions
    /// {
    ///     public const string Read = "users.read";
    ///     public const string Write = "users.write";
    /// }
    ///
    /// var claims = new List&lt;Claim&gt;();
    /// claims.AddPermissionByClass(typeof(UserPermissions));
    /// // Results in 2 permission claims
    /// </code>
    /// </example>
    public static void AddPermissionByClass(this List<Claim> claims, Type classType)
    {
        claims.AddByClass(ClaimTypes.Permission, classType);
    }
}