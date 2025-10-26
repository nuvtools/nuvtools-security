using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace NuvTools.Security.AspNetCore.Extensions;

/// <summary>
/// Provides extension methods for configuring authorization policies based on specific claims.
/// </summary>
public static class AuthorizationOptionsExtensions
{
    /// <summary>
    /// Adds an authorization policy that requires a specific permission claim.
    /// </summary>
    /// <param name="options">The <see cref="AuthorizationOptions"/> to which the policy will be added.</param>
    /// <param name="name">The unique name of the policy.</param>
    /// <param name="values">The required permission claim values.</param>
    /// <remarks>
    /// This is a convenience method for adding policies that check for a <c>Permission</c> claim type.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> or <paramref name="name"/> is <see langword="null"/> or empty.</exception>
    /// <exception cref="ArgumentException">Thrown when no claim values are provided.</exception>
    public static void AddPolicyWithRequiredPermissionClaim(this AuthorizationOptions options, string name, params string[] values)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentNullException(nameof(name), "Policy name cannot be null or whitespace.");

        if (values == null || values.Length == 0)
            throw new ArgumentException("At least one permission value is required.", nameof(values));

        options.AddPolicyWithRequiredClaim(name, Models.ClaimTypes.Permission, values);
    }

    /// <summary>
    /// Adds an authorization policy that requires one or more specific claims.
    /// </summary>
    /// <param name="options">The <see cref="AuthorizationOptions"/> to which the policy will be added.</param>
    /// <param name="name">The unique name of the policy.</param>
    /// <param name="claims">The required claims for the policy.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> or <paramref name="name"/> is <see langword="null"/> or empty.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="claims"/> is empty or contains invalid claim definitions.</exception>
    /// <remarks>
    /// Each claim is validated to ensure that its <see cref="Claim.Type"/> and <see cref="Claim.Value"/> are not empty.
    /// </remarks>
    public static void AddPolicyWithRequiredClaim(this AuthorizationOptions options, string name, params Claim[] claims)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentNullException(nameof(name), "Policy name cannot be null or whitespace.");

        if (claims == null || claims.Length == 0)
            throw new ArgumentException("At least one claim must be provided.", nameof(claims));

        options.AddPolicy(name, policy =>
        {
            foreach (var claim in claims)
            {
                if (string.IsNullOrWhiteSpace(claim.Type))
                    throw new ArgumentException("Claim type cannot be null or whitespace.", nameof(claims));

                if (string.IsNullOrWhiteSpace(claim.Value))
                    throw new ArgumentException("Claim value cannot be null or whitespace.", nameof(claims));

                policy.RequireClaim(claim.Type, claim.Value);
            }
        });
    }

    /// <summary>
    /// Adds an authorization policy that requires a claim of a specific type with one or more allowed values.
    /// </summary>
    /// <param name="options">The <see cref="AuthorizationOptions"/> to which the policy will be added.</param>
    /// <param name="name">The unique name of the policy.</param>
    /// <param name="type">The type of claim to check.</param>
    /// <param name="values">The required claim values.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/>, <paramref name="name"/>, or <paramref name="type"/> is null or whitespace.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="values"/> is empty.</exception>
    /// <remarks>
    /// Use this overload when you want to define a policy based on a single claim type but multiple possible values.
    /// </remarks>
    public static void AddPolicyWithRequiredClaim(this AuthorizationOptions options, string name, string type, params string[] values)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentNullException(nameof(name), "Policy name cannot be null or whitespace.");

        if (string.IsNullOrWhiteSpace(type))
            throw new ArgumentNullException(nameof(type), "Claim type cannot be null or whitespace.");

        if (values == null || values.Length == 0)
            throw new ArgumentException("At least one claim value is required.", nameof(values));

        options.AddPolicy(name, policy => policy.RequireClaim(type, values));
    }
}