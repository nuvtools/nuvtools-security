namespace NuvTools.Security.Models;

/// <summary>
/// Provides constant values for commonly used claim type names in JWT and OIDC authentication.
/// </summary>
/// <remarks>
/// These constants represent standard claim names from OpenID Connect and JWT specifications,
/// commonly used for extracting user identity information from tokens.
/// </remarks>
public static class ClaimConstants
{
    /// <summary>
    /// The given name (first name) of the user.
    /// Standard OIDC claim name.
    /// </summary>
    public const string GivenName = "given_name";

    /// <summary>
    /// The family name (last name) of the user.
    /// Standard OIDC claim name.
    /// </summary>
    public const string FamilyName = "family_name";

    /// <summary>
    /// The email address of the user.
    /// Standard OIDC claim name.
    /// </summary>
    public const string Email = "email";

    /// <summary>
    /// The subject identifier - unique identifier for the user.
    /// Standard JWT claim name.
    /// </summary>
    public const string Sub = "sub";

    /// <summary>
    /// User Principal Name - typically used in Microsoft Azure AD and Active Directory scenarios.
    /// </summary>
    public const string Upn = "upn";

    /// <summary>
    /// The preferred username for the user.
    /// Standard OIDC claim name.
    /// </summary>
    public const string PreferredUsername = "preferred_username";

    /// <summary>
    /// The unique name of the user - often used in legacy authentication systems.
    /// </summary>
    public const string UniqueName = "unique_name";
}