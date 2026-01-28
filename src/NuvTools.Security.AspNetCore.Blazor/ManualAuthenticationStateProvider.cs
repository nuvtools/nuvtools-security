using Microsoft.AspNetCore.Components.Authorization;
using NuvTools.AspNetCore.Blazor.JSInterop;
using NuvTools.Security.Helpers;
using System.Security.Claims;

namespace NuvTools.Security.AspNetCore.Blazor;

/// <summary>
/// Provides a manual implementation of <see cref="AuthenticationStateProvider"/> that manages user authentication state
/// using JWT tokens stored in browser local storage.
/// </summary>
/// <remarks>
/// This provider enables custom authentication logic in Blazor applications, typically used when not relying on built-in
/// authentication mechanisms like OpenID Connect or Azure AD.
/// </remarks>
public class ManualAuthenticationStateProvider(ILocalStorageService storage) : AuthenticationStateProvider
{
    private const string TokenKey = "authToken";

    /// <summary>
    /// Gets the current authenticated user.
    /// </summary>
    public ClaimsPrincipal? CurrentUser { get; private set; }

    /// <summary>
    /// Signs the user in by validating the provided JWT token and updating the authentication state.
    /// </summary>
    /// <param name="token">The JWT token used to authenticate the user.</param>
    /// <remarks>
    /// If the token is expired or invalid, the user will be automatically signed out.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="token"/> is null or empty.</exception>
    public async Task SignInAsync(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            throw new ArgumentNullException(nameof(token), "JWT token cannot be null or empty.");

        if (JwtHelper.IsTokenExpired(token))
        {
            await SignOutAsync();
            return;
        }

        await storage.SetItemAsync(TokenKey, token);

        var user = CreateUserFromToken(token);
        CurrentUser = user;

        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(user)));
    }

    /// <summary>
    /// Signs the user out by removing the stored token and setting the authentication state to anonymous.
    /// </summary>
    public async Task SignOutAsync()
    {
        await storage.RemoveItemAsync(TokenKey);

        var anonymous = new ClaimsPrincipal(new ClaimsIdentity());
        CurrentUser = anonymous;

        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(anonymous)));
    }

    /// <summary>
    /// Gets the current authentication state by reading the JWT token from local storage.
    /// </summary>
    /// <returns>
    /// An <see cref="AuthenticationState"/> representing the current user or an anonymous identity if no valid token exists.
    /// </returns>
    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var token = await storage.GetItemAsync<string>(TokenKey);

        if (string.IsNullOrWhiteSpace(token) || JwtHelper.IsTokenExpired(token))
        {
            var anonymous = new ClaimsPrincipal(new ClaimsIdentity());
            CurrentUser = anonymous;
            return new AuthenticationState(anonymous);
        }

        var user = CreateUserFromToken(token);
        CurrentUser = user;

        return new AuthenticationState(user);
    }

    /// <summary>
    /// Creates a <see cref="ClaimsPrincipal"/> from a valid JWT token.
    /// </summary>
    /// <param name="token">The JWT token containing the user claims.</param>
    /// <returns>
    /// A <see cref="ClaimsPrincipal"/> representing the authenticated user.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="token"/> is null or empty.</exception>
    private static ClaimsPrincipal CreateUserFromToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            throw new ArgumentNullException(nameof(token), "JWT token cannot be null or empty.");

        var claims = JwtHelper.ParseClaimsFromJwt(token);
        var identity = new ClaimsIdentity(claims, authenticationType: "manual");

        return new ClaimsPrincipal(identity);
    }
}