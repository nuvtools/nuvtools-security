using NuvTools.Security.Models;
using System.Security.Claims;

namespace NuvTools.Security.Extensions;

public static class ClaimsPrincipalExtensions
{
    public static string GetId(this ClaimsPrincipal user)
    {
        return user.FindFirst(ClaimConstants.Sub)!.Value;
    }

    public static string? GetGivenName(this ClaimsPrincipal user)
    {
        return user.FindFirst(ClaimConstants.GivenName)?.Value;
    }
    public static string? GetFamilyName(this ClaimsPrincipal user)
    {
        return user.FindFirst(ClaimConstants.FamilyName)?.Value;
    }

    public static string? GetEmail(this ClaimsPrincipal user)
    {
        string? email = user.FindFirst("email")?.Value
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