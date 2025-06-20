using NuvTools.Security.Models;
using System.Security.Claims;
using ClaimTypes = System.Security.Claims.ClaimTypes;

namespace NuvTools.Security.Extensions;

public static class ClaimsPrincipalExtensions
{
    public static string GetId(this ClaimsPrincipal user)
    {
        var id = user.FindFirst(ClaimTypes.NameIdentifier)?.Value
              ?? user.FindFirst(ClaimConstants.Sub)?.Value;

        if (string.IsNullOrWhiteSpace(id))
            throw new InvalidOperationException("User ID claim not found.");

        return id;
    }

    public static string? GetName(this ClaimsPrincipal user)
    {
        var name = user.FindFirst(ClaimTypes.Name)?.Value
               ?? user.FindFirst("name")?.Value 
               ?? user.FindFirst(ClaimConstants.GivenName)?.Value;

        return name;
    }

    public static string? GetSurname(this ClaimsPrincipal user)
    {
        var surname = user.FindFirst(ClaimTypes.Surname)?.Value;

        if (string.IsNullOrEmpty(surname))
            surname = user.FindFirst("family_name")?.Value;

        return surname;
    }

    public static string? GetEmail(this ClaimsPrincipal user)
    {
        var email = user.FindFirst(ClaimTypes.Email)?.Value;
                
        if (string.IsNullOrEmpty(email))
            email = user.FindFirst("email")?.Value
                     ?? user.FindFirst("upn")?.Value
                     ?? user.FindFirst("preferred_username")?.Value
                     ?? user.FindFirst("unique_name")?.Value;

        return !string.IsNullOrEmpty(email) && Validation.Validator.IsEmail(email) ? email : null;
    }

    public static bool HasValue<T>(this ClaimsPrincipal user, string customAttriuteName, T value)
    {
        IEnumerable<T>? values = user.GetCustomAttributeValues<T>(customAttriuteName);
        if (values == null || !values.Any()) return false;

        return values.Contains(value);
    }

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