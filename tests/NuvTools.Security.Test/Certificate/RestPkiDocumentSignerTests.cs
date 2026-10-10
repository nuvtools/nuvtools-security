using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using NuvTools.Security.Certificate.Lacuna;
using NuvTools.Security.Certificate.Lacuna.Extensions;
using NuvTools.Security.Certificate.Signing;
using NUnit.Framework;

namespace NuvTools.Security.Test.Certificate;

[TestFixture]
public class RestPkiDocumentSignerTests
{
    // Nothing listens here, so every call to the provider fails at the connection.
    private const string UnreachableEndpoint = "http://127.0.0.1:9/";

    private static readonly byte[] Pdf = [0x25, 0x50, 0x44, 0x46];

    private static IDocumentSigner Create(string policy = RestPkiOptions.BasicPadesSignaturePolicy)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["RestPki:Endpoint"] = UnreachableEndpoint,
                ["RestPki:AccessToken"] = "access-token",
                ["RestPki:PadesSignaturePolicy"] = policy
            })
            .Build();

        var services = new ServiceCollection();
        services.AddLacunaDocumentSigning(configuration);

        return services.BuildServiceProvider().GetRequiredService<IDocumentSigner>();
    }

    [Test]
    public void Registration_ResolvesTheRestPkiSigner()
    {
        Assert.That(Create(), Is.InstanceOf<RestPkiDocumentSigner>());
    }

    [Test]
    public void UnknownPolicy_FailsWhenTheSignerIsCreated()
    {
        Assert.That(() => Create("NotAPolicy"), Throws.InvalidOperationException);
    }

    // Signing is not an access decision: a provider failure is not turned into a result.
    [Test]
    public void ProviderOutOfReach_PropagatesFromStart()
    {
        Assert.That(async () => await Create().StartAsync(new DocumentSignatureRequest(Pdf)), Throws.Exception);
    }

    [Test]
    public void ProviderOutOfReach_PropagatesFromComplete()
    {
        Assert.That(async () => await Create().CompleteAsync("signed-token"), Throws.Exception);
    }

    [TestCase("")]
    [TestCase("  ")]
    public void MissingToken_IsRefusedBeforeTheProviderIsCalled(string token)
    {
        Assert.That(async () => await Create().CompleteAsync(token), Throws.InstanceOf<ArgumentException>());
    }
}
