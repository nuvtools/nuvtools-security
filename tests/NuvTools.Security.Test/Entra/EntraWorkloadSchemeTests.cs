using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using NUnit.Framework;
using NuvTools.Security.AspNetCore.Entra;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;

namespace NuvTools.Security.Test;

/// <summary>
/// The Entra workload scheme against tokens shaped like a managed identity's, signed by a key the test
/// host is told to trust in place of Entra's published ones.
/// </summary>
[TestFixture]
public class EntraWorkloadSchemeTests
{
    private const string Scheme = "Workload";
    private const string TenantId = "11111111-1111-1111-1111-111111111111";
    private const string Audience = "api://11111111-1111-1111-1111-111111111111/receiver-test";
    private const string AllowedApp = "22222222-2222-2222-2222-222222222222";

    private static readonly SecurityKey Key = new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32));

    private static async Task<HttpClient> HostAsync(bool configured = true)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();

        builder.Services.AddAuthentication().AddEntraWorkload(Scheme, options =>
        {
            if (!configured) return;

            options.TenantId = TenantId;
            options.Audience = Audience;
            options.AllowedApplicationIds = [AllowedApp];
        });

        builder.Services.AddAuthorization();

        // Entra's keys, replaced by the test's own; nothing reaches login.microsoftonline.com.
        if (configured)
            builder.Services.Configure<JwtBearerOptions>(Scheme, options =>
                options.Configuration = new OpenIdConnectConfiguration { SigningKeys = { Key } });

        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/", (HttpContext context) => context.User.GetEntraWorkloadApplicationId())
            .RequireAuthorization(policy => policy.AddAuthenticationSchemes(Scheme).RequireAuthenticatedUser());

        await app.StartAsync();

        return app.GetTestClient();
    }

    private static string Token(
        string issuer = $"https://sts.windows.net/{TenantId}/",
        string audience = Audience,
        string applicationClaim = EntraWorkloadClaims.ApplicationIdV1,
        string applicationId = AllowedApp) =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Claims = new Dictionary<string, object> { [applicationClaim] = applicationId },
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(Key, SecurityAlgorithms.HmacSha256)
        });

    private static async Task<HttpResponseMessage> CallAsync(HttpClient client, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        return await client.SendAsync(request);
    }

    [Test]
    public async Task AnAllowedManagedIdentity_IsAdmitted_WithItsApplicationId()
    {
        using var client = await HostAsync();

        var response = await CallAsync(client, Token());

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(await response.Content.ReadAsStringAsync(), Is.EqualTo(AllowedApp));
    }

    [Test]
    public async Task AV2Token_IsAdmittedToo()
    {
        using var client = await HostAsync();

        var response = await CallAsync(client, Token(
            issuer: $"https://login.microsoftonline.com/{TenantId}/v2.0",
            applicationClaim: EntraWorkloadClaims.ApplicationIdV2));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task AnotherApplication_IsRefused()
    {
        using var client = await HostAsync();

        var response = await CallAsync(client, Token(applicationId: "33333333-3333-3333-3333-333333333333"));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task ATokenForAnotherAudience_IsRefused()
    {
        using var client = await HostAsync();

        var response = await CallAsync(client, Token(audience: "api://other"));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task ATokenFromAnotherTenant_IsRefused()
    {
        using var client = await HostAsync();

        var response = await CallAsync(client, Token(issuer: "https://sts.windows.net/99999999-9999-9999-9999-999999999999/"));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Unconfigured_RefusesEverybody()
    {
        using var client = await HostAsync(configured: false);

        var response = await CallAsync(client, Token());

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public void TheOptions_AreConfiguredOnlyWithAllThree()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(new EntraWorkloadOptions().IsConfigured, Is.False);
            Assert.That(new EntraWorkloadOptions { TenantId = TenantId, Audience = Audience }.IsConfigured, Is.False);
            Assert.That(new EntraWorkloadOptions { TenantId = TenantId, Audience = Audience, AllowedApplicationIds = [" "] }.IsConfigured, Is.False);
            Assert.That(new EntraWorkloadOptions { TenantId = TenantId, Audience = Audience, AllowedApplicationIds = [AllowedApp] }.IsConfigured, Is.True);
        }
    }
}
