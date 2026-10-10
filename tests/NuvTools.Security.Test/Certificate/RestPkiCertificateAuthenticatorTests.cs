using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using NuvTools.Security.Certificate;
using NuvTools.Security.Certificate.Lacuna.Extensions;
using NuvTools.Security.Certificate.Lacuna;
using NUnit.Framework;

namespace NuvTools.Security.Test.Certificate;

[TestFixture]
public class RestPkiCertificateAuthenticatorTests
{
    // Nothing listens here, so every call to the provider fails at the connection.
    private const string UnreachableEndpoint = "http://127.0.0.1:9/";

    private static ICertificateAuthenticator Create(string securityContext = RestPkiOptions.PkiBrazilSecurityContext)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["RestPki:Endpoint"] = UnreachableEndpoint,
                ["RestPki:AccessToken"] = "access-token",
                ["RestPki:SecurityContext"] = securityContext
            })
            .Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddLacunaCertificateAuthentication(configuration);

        return services.BuildServiceProvider().GetRequiredService<ICertificateAuthenticator>();
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("  ")]
    public async Task MissingToken_IsRejected(string? token)
    {
        var result = await Create().CompleteAsync(token);

        Assert.Multiple(() =>
        {
            Assert.That(result.Valid, Is.False);
            Assert.That(result.Subject, Is.Null);
            Assert.That(result.Failure, Is.EqualTo(CertificateFailureType.Rejected));
        });
    }

    [Test]
    public async Task ProviderOutOfReach_FailsClosed()
    {
        var result = await Create().CompleteAsync("signed-token");

        Assert.Multiple(() =>
        {
            Assert.That(result.Valid, Is.False);
            Assert.That(result.Subject, Is.Null);
            Assert.That(result.Failure, Is.EqualTo(CertificateFailureType.Unavailable));
        });
    }

    [Test]
    public void UnknownSecurityContext_FailsWhenTheAuthenticatorIsCreated()
    {
        Assert.That(() => Create("NotAContext"), Throws.InvalidOperationException);
    }
}
