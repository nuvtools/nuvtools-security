using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication;
using NuvTools.Security.Helpers;

namespace NuvTools.Security.AspNetCore.Blazor;

/// <summary>
/// Provides an <see cref="AuthenticationStateProvider"/> implementation for Blazor WebAssembly
/// applications that use OpenID Connect (OIDC) authentication.
/// </summary>
/// <remarks>
/// This provider retrieves and parses access tokens using an <see cref="IAccessTokenProvider"/>,
/// enabling JWT-based user claims to be extracted and tracked for authorization.
/// </remarks>
public class OidcAuthenticationStateProvider(IAccessTokenProvider tokenProvider) : AuthenticationStateProvider
{
    /// <summary>
    /// Gets the current authenticated user represented by a <see cref="ClaimsPrincipal"/>.
    /// </summary>
    public ClaimsPrincipal? CurrentUser { get; private set; }

    /// <summary>
    /// Asynchronously retrieves the current authentication state.
    /// </summary>
    /// <returns>
    /// An <see cref="AuthenticationState"/> representing either the authenticated user or
    /// an anonymous identity if the token could not be obtained or is invalid.
    /// </returns>
    /// <remarks>
    /// This method is called by the Blazor authorization infrastructure to determine
    /// the current user’s identity. If a valid access token is present, it will parse the
    /// claims from the JWT; otherwise, it returns an anonymous user.
    /// </remarks>
    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        ArgumentNullException.ThrowIfNull(tokenProvider);

        var tokenResult = await tokenProvider.RequestAccessToken();

        // When the access token cannot be retrieved or is empty, return an anonymous user.
        if (!tokenResult.TryGetToken(out var token) || string.IsNullOrWhiteSpace(token.Value))
        {
            var anonymous = CreateAnonymousUser();
            CurrentUser = anonymous;
            return new AuthenticationState(anonymous);
        }

        // Parse claims from JWT and create authenticated user
        var user = CreateUserFromToken(token.Value);
        CurrentUser = user;

        return new AuthenticationState(user);
    }

    /// <summary>
    /// Creates a <see cref="ClaimsPrincipal"/> from a JWT token string.
    /// </summary>
    /// <param name="token">The JWT token to parse.</param>
    /// <returns>A <see cref="ClaimsPrincipal"/> representing the authenticated user.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="token"/> is null or whitespace.</exception>
    private static ClaimsPrincipal CreateUserFromToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            throw new ArgumentNullException(nameof(token), "Token cannot be null or empty.");

        var claims = JwtHelper.ParseClaimsFromJwt(token);
        var identity = new ClaimsIdentity(claims, authenticationType: "oidc");
        return new ClaimsPrincipal(identity);
    }

    /// <summary>
    /// Creates an anonymous user with no identity or claims.
    /// </summary>
    /// <returns>A <see cref="ClaimsPrincipal"/> representing an unauthenticated user.</returns>
    private static ClaimsPrincipal CreateAnonymousUser() =>
        new(new ClaimsIdentity());
}