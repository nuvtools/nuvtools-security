using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication;
using NuvTools.Security.Util;

namespace NuvTools.Security.AspNetCore.Blazor;

public class OidcAuthenticationStateProvider(IAccessTokenProvider tokenProvider) : AuthenticationStateProvider
{
    public ClaimsPrincipal? CurrentUser { get; private set; }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var tokenResult = await tokenProvider.RequestAccessToken();

        if (!tokenResult.TryGetToken(out var token) || string.IsNullOrWhiteSpace(token.Value))
        {
            var anonymous = new ClaimsPrincipal(new ClaimsIdentity());
            CurrentUser = anonymous;
            return new AuthenticationState(anonymous);
        }

        var claims = JwtHelper.ParseClaimsFromJwt(token.Value);
        var identity = new ClaimsIdentity(claims, "oidc");
        var user = new ClaimsPrincipal(identity);

        CurrentUser = user;

        return new AuthenticationState(user);
    }
}