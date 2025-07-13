using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;
using NuvTools.Security.Helpers;
using System.Security.Claims;

namespace NuvTools.Security.AspNetCore.Blazor;

public class ManualAuthenticationStateProvider(ILocalStorageService storage) : AuthenticationStateProvider
{
    private const string TokenKey = "authToken";

    public ClaimsPrincipal? CurrentUser { get; private set; }

    public async Task SignInAsync(string token)
    {
        if (JwtHelper.IsTokenExpired(token))
        {
            await SignOutAsync();
            return;
        }

        await storage.SetItemAsync(TokenKey, token);

        var claims = JwtHelper.ParseClaimsFromJwt(token);
        var identity = new ClaimsIdentity(claims, "manual");
        var user = new ClaimsPrincipal(identity);

        CurrentUser = user;

        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(user)));
    }

    public async Task SignOutAsync()
    {
        await storage.RemoveItemAsync(TokenKey);

        var anonymous = new ClaimsPrincipal(new ClaimsIdentity());
        CurrentUser = anonymous;

        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(anonymous)));
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var token = await storage.GetItemAsync<string>(TokenKey);

        if (string.IsNullOrWhiteSpace(token))
        {
            var anonymous = new ClaimsPrincipal(new ClaimsIdentity());
            CurrentUser = anonymous;
            return new AuthenticationState(anonymous);
        }

        var user = CreateUserFromToken(token);
        CurrentUser = user;
        return new AuthenticationState(user);
    }

    private static ClaimsPrincipal CreateUserFromToken(string token)
    {
        var claims = JwtHelper.ParseClaimsFromJwt(token);
        var identity = new ClaimsIdentity(claims, "manual");
        return new ClaimsPrincipal(identity);
    }
}