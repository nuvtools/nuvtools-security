using NuvTools.Security.Models;
using System.Security.Claims;
using ClaimTypes = System.Security.Claims.ClaimTypes;

namespace NuvTools.Security.Extensions;

/// <summary>
/// Provides extension methods for extracting user information from <see cref="ClaimsPrincipal"/> objects.
/// </summary>
/// <remarks>
/// These extensions simplify the process of extracting common user identity information from claims,
/// handling multiple claim type variations and validating values where appropriate.
/// </remarks>
public static class ClaimsPrincipalExtensions
{
    /// <summary>
    /// Gets the unique identifier of the user from either the NameIdentifier or Sub claim.
    /// </summary>
    /// <param name="user">The claims principal representing the user.</param>
    /// <returns>The user's unique identifier.</returns>
    /// <exception cref="InvalidOperationException">Thrown when neither NameIdentifier nor Sub claim is present.</exception>
    /// <remarks>
    /// This method first tries to get the NameIdentifier claim, then falls back to the Sub claim.
    /// At least one of these claims must be present.
    /// </remarks>
    public static string GetId(this ClaimsPrincipal user)
    {
        var id = user.FindFirst(ClaimTypes.NameIdentifier)?.Value
              ?? user.FindFirst(ClaimConstants.Sub)?.Value;

        if (string.IsNullOrWhiteSpace(id))
            throw new InvalidOperationException("User ID claim not found.");

        return id;
    }

    /// <summary>
    /// Gets the subject identifier (sub claim) of the user.
    /// </summary>
    /// <param name="user">The claims principal representing the user.</param>
    /// <returns>The subject identifier, or null if not present.</returns>
    /// <remarks>
    /// The 'sub' claim is the standard JWT claim for the unique user identifier.
    /// </remarks>
    public static string? GetSub(this ClaimsPrincipal user)
    {
        return user.FindFirst(ClaimConstants.Sub)?.Value;
    }

    /// <summary>
    /// Gets the name identifier claim of the user.
    /// </summary>
    /// <param name="user">The claims principal representing the user.</param>
    /// <returns>The name identifier, or null if not present.</returns>
    /// <remarks>
    /// This is typically used in ASP.NET Identity-based authentication systems.
    /// </remarks>
    public static string? GetNameIdentifier(this ClaimsPrincipal user)
    {
        return user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    }

    /// <summary>
    /// Gets the display name of the user.
    /// </summary>
    /// <param name="user">The claims principal representing the user.</param>
    /// <returns>The user's display name, or null if not present.</returns>
    /// <remarks>
    /// This method checks both the standard ClaimTypes.Name and the "name" claim.
    /// </remarks>
    public static string? GetName(this ClaimsPrincipal user)
    {
        var name = user.FindFirst(ClaimTypes.Name)?.Value
               ?? user.FindFirst("name")?.Value;

        return name;
    }

    /// <summary>
    /// Gets the given name (first name) of the user.
    /// </summary>
    /// <param name="user">The claims principal representing the user.</param>
    /// <returns>The user's given name, or null if not present.</returns>
    public static string? GetGivenName(this ClaimsPrincipal user)
    {
        return user.FindFirst(ClaimConstants.GivenName)?.Value;
    }

    /// <summary>
    /// Gets the surname (last name) of the user from the Surname claim.
    /// </summary>
    /// <param name="user">The claims principal representing the user.</param>
    /// <returns>The user's surname, or null if not present.</returns>
    /// <remarks>
    /// This uses the standard ClaimTypes.Surname claim type.
    /// For OIDC tokens, use <see cref="GetFamilyName"/> instead.
    /// </remarks>
    public static string? GetSurname(this ClaimsPrincipal user)
    {
        var surname = user.FindFirst(ClaimTypes.Surname)?.Value;

        return surname;
    }

    /// <summary>
    /// Gets the family name (last name) of the user from the OIDC family_name claim.
    /// </summary>
    /// <param name="user">The claims principal representing the user.</param>
    /// <returns>The user's family name, or null if not present.</returns>
    /// <remarks>
    /// This uses the OIDC standard "family_name" claim.
    /// For traditional ASP.NET claims, use <see cref="GetSurname"/> instead.
    /// </remarks>
    public static string? GetFamilyName(this ClaimsPrincipal user)
    {
        return user.FindFirst(ClaimConstants.FamilyName)?.Value;
    }

    /// <summary>
    /// Gets the email address of the user, checking multiple claim sources and validating the format.
    /// </summary>
    /// <param name="user">The claims principal representing the user.</param>
    /// <returns>A valid email address, or null if not found or invalid.</returns>
    /// <remarks>
    /// This method checks the following claims in order: Email, email (OIDC), UPN, PreferredUsername, UniqueName.
    /// The value is validated to ensure it's a properly formatted email address before returning.
    /// </remarks>
    public static string? GetEmail(this ClaimsPrincipal user)
    {
        var email = user.FindFirst(ClaimTypes.Email)?.Value
                 ?? user.FindFirst(ClaimConstants.Email)?.Value
                 ?? user.FindFirst(ClaimConstants.Upn)?.Value
                 ?? user.FindFirst(ClaimConstants.PreferredUsername)?.Value
                 ?? user.FindFirst(ClaimConstants.UniqueName)?.Value;

        return !string.IsNullOrEmpty(email) && Validation.Validator.IsEmail(email) ? email : null;
    }

    /// <summary>
    /// Gets the User Principal Name (UPN) of the user.
    /// </summary>
    /// <param name="user">The claims principal representing the user.</param>
    /// <returns>The UPN, or null if not present.</returns>
    /// <remarks>
    /// UPN is commonly used in Microsoft Azure AD and Active Directory scenarios.
    /// It typically has the format username@domain.
    /// </remarks>
    public static string? GetUpn(this ClaimsPrincipal user)
    {
        return user.FindFirst(ClaimConstants.Upn)?.Value;
    }

    /// <summary>
    /// Gets the preferred username of the user.
    /// </summary>
    /// <param name="user">The claims principal representing the user.</param>
    /// <returns>The preferred username, or null if not present.</returns>
    /// <remarks>
    /// This is a standard OIDC claim representing the user's preferred display username.
    /// </remarks>
    public static string? GetPreferredUsername(this ClaimsPrincipal user)
    {
        return user.FindFirst(ClaimConstants.PreferredUsername)?.Value;
    }

    /// <summary>
    /// Gets the unique name of the user.
    /// </summary>
    /// <param name="user">The claims principal representing the user.</param>
    /// <returns>The unique name, or null if not present.</returns>
    /// <remarks>
    /// This is often used in legacy authentication systems as a unique identifier.
    /// </remarks>
    public static string? GetUniqueName(this ClaimsPrincipal user)
    {
        return user.FindFirst(ClaimConstants.UniqueName)?.Value;
    }

    /// <summary>
    /// Determines whether the user has a specific value in a custom extension attribute claim.
    /// </summary>
    /// <typeparam name="T">The type to parse the attribute values as (string, int, double, bool, or enum).</typeparam>
    /// <param name="user">The claims principal representing the user.</param>
    /// <param name="customAttriuteName">The name of the custom attribute (without the "extension_" prefix).</param>
    /// <param name="value">The value to check for.</param>
    /// <returns>True if the user has the specified value in the custom attribute; otherwise, false.</returns>
    /// <remarks>
    /// This method looks for a claim with type "extension_{customAttributeName}" and checks if
    /// the specified value exists in the comma-separated list of values.
    /// </remarks>
    public static bool HasValue<T>(this ClaimsPrincipal user, string customAttriuteName, T value)
    {
        IEnumerable<T>? values = user.GetCustomAttributeValues<T>(customAttriuteName);
        if (values == null || !values.Any()) return false;

        return values.Contains(value);
    }

    /// <summary>
    /// Gets all values from a custom extension attribute claim and parses them as the specified type.
    /// </summary>
    /// <typeparam name="T">The type to parse the attribute values as (string, int, double, bool, or enum).</typeparam>
    /// <param name="user">The claims principal representing the user.</param>
    /// <param name="customAttributeName">The name of the custom attribute (without the "extension_" prefix).</param>
    /// <returns>
    /// A collection of parsed values, or null if the claim doesn't exist.
    /// Invalid values are filtered out for enum types.
    /// </returns>
    /// <exception cref="NotSupportedException">Thrown when the type T is not supported.</exception>
    /// <exception cref="FormatException">Thrown when values cannot be parsed to the specified type.</exception>
    /// <remarks>
    /// <para>
    /// This method looks for a claim with type "extension_{customAttributeName}" and expects
    /// a comma-separated list of values. It parses each value to the specified type.
    /// </para>
    /// <para>Supported types: string, int, double, bool, and enum types.</para>
    /// <para>
    /// This is commonly used with Azure AD B2C custom attributes that are passed as extension claims.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Get a list of role IDs stored as integers in an extension attribute
    /// var roleIds = user.GetCustomAttributeValues&lt;int&gt;("roleIds");
    ///
    /// // Get an enum value from a custom attribute
    /// var permissions = user.GetCustomAttributeValues&lt;PermissionLevel&gt;("permissions");
    /// </code>
    /// </example>
    public static IEnumerable<T>? GetCustomAttributeValues<T>(this ClaimsPrincipal user, string customAttributeName)
    {
        string? claimValue = user?.Claims
            .FirstOrDefault(c => c.Type == $"extension_{customAttributeName}")?.Value;

        if (string.IsNullOrWhiteSpace(claimValue))
            return null;

        string[] values = claimValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        Type targetType = typeof(T);

        try
        {
            if (typeof(T).IsEnum)
            {
                return [.. values
                    .Select(v => Enum.TryParse(typeof(T), v, true, out object? result) ? result : null)
                    .Where(r => r is not null)
                    .Cast<T>()];
            }

            return targetType switch
            {
                var t when t == typeof(int) => [.. values.Select(v => (T)(object)int.Parse(v))],
                var t when t == typeof(double) => [.. values.Select(v => (T)(object)double.Parse(v))],
                var t when t == typeof(bool) => [.. values.Select(v => (T)(object)bool.Parse(v))],
                var t when t == typeof(string) => values.Cast<T>().ToList(),
                _ => throw new NotSupportedException($"Type {targetType.Name} is not supported.")
            };
        }
        catch (Exception ex)
        {
            throw new FormatException($"Failed to parse values for type {targetType.Name}.", ex);
        }
    }
}
