using System.Net;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using NuvTools.Security.Biometrics;
using NuvTools.Security.Biometrics.Serpro.Extensions;
using NUnit.Framework;

namespace NuvTools.Security.Test.Biometrics;

[TestFixture]
public class DatavalidFaceVerifierTests
{
    private const string TokenUrl = "https://serpro.test/token";
    private const string ValidateUrl = "https://serpro.test/datavalid/pf-facial";
    private const string ValidCpf = "529.982.247-25";

    private static readonly byte[] Image = [1, 2, 3, 4];

    private readonly ManualTimeProvider _clock = new();

    private static HttpResponseMessage Json(HttpStatusCode status, string body)
        => new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static HttpResponseMessage Token(int expiresIn = 3600)
        => Json(HttpStatusCode.OK, $$"""{"access_token":"token-abc","token_type":"Bearer","expires_in":{{expiresIn}}}""");

    private static HttpResponseMessage Face(double similarity, bool available = true, string liveness = "")
        => Json(HttpStatusCode.OK,
            $$$"""{"biometria_facial":{"disponivel":{{{(available ? "true" : "false")}}},"probabilidade":"Alta","similaridade":{{{similarity.ToString(System.Globalization.CultureInfo.InvariantCulture)}}},"vivacidade":"{{{liveness}}}"}}""");

    private static bool IsTokenRequest(HttpRequestMessage request)
        => request.RequestUri!.AbsoluteUri == TokenUrl;

    private (IFaceVerifier Verifier, StubHttpMessageHandler Handler) Create(
        Func<HttpRequestMessage, HttpResponseMessage> validate,
        Func<HttpRequestMessage, HttpResponseMessage>? token = null,
        params string[] acceptedLiveness)
    {
        var settings = new Dictionary<string, string?>
        {
            ["Datavalid:TokenUrl"] = TokenUrl,
            ["Datavalid:ValidateUrl"] = ValidateUrl,
            ["Datavalid:ConsumerKey"] = "key",
            ["Datavalid:ConsumerSecret"] = "secret",
            ["Datavalid:MinSimilarity"] = "0.9"
        };

        for (var i = 0; i < acceptedLiveness.Length; i++)
            settings[$"Datavalid:AcceptedLiveness:{i}"] = acceptedLiveness[i];

        var handler = new StubHttpMessageHandler(request => IsTokenRequest(request) ? (token ?? (_ => Token()))(request) : validate(request));

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<TimeProvider>(_clock);
        services.AddSerproFaceVerification(new ConfigurationBuilder().AddInMemoryCollection(settings).Build());
        services.ConfigureAll<HttpClientFactoryOptions>(options =>
            options.HttpMessageHandlerBuilderActions.Add(builder => builder.PrimaryHandler = handler));

        return (services.BuildServiceProvider().GetRequiredService<IFaceVerifier>(), handler);
    }

    private static FaceVerificationRequest Request(string cpf = ValidCpf) => new(cpf, Image);

    [Test]
    public async Task SimilarityAtTheMinimum_IsAccepted()
    {
        var (verifier, _) = Create(_ => Face(0.9));

        var result = await verifier.VerifyAsync(Request());

        Assert.Multiple(() =>
        {
            Assert.That(result.Matched, Is.True);
            Assert.That(result.Similarity, Is.EqualTo(0.9));
            Assert.That(result.Failure, Is.EqualTo(FaceVerificationFailureType.None));
        });
    }

    [Test]
    public async Task SimilarityBelowTheMinimum_IsRefusedAndReported()
    {
        var (verifier, _) = Create(_ => Face(0.89));

        var result = await verifier.VerifyAsync(Request());

        Assert.Multiple(() =>
        {
            Assert.That(result.Matched, Is.False);
            Assert.That(result.Similarity, Is.EqualTo(0.89));
            Assert.That(result.Failure, Is.EqualTo(FaceVerificationFailureType.NotMatched));
        });
    }

    [Test]
    public async Task NoFaceOnRecord_IsRefused()
    {
        var (verifier, _) = Create(_ => Face(0, available: false));

        var result = await verifier.VerifyAsync(Request());

        Assert.That(result.Failure, Is.EqualTo(FaceVerificationFailureType.FaceNotOnRecord));
    }

    [Test]
    public async Task InvalidCpf_IsRefusedWithoutCallingTheProvider()
    {
        var (verifier, handler) = Create(_ => Face(1));

        var result = await verifier.VerifyAsync(Request("111.111.111-11"));

        Assert.Multiple(() =>
        {
            Assert.That(result.Failure, Is.EqualTo(FaceVerificationFailureType.InvalidDocument));
            Assert.That(handler.Requests, Is.Empty);
        });
    }

    [Test]
    public async Task EmptyImage_IsRefusedWithoutCallingTheProvider()
    {
        var (verifier, handler) = Create(_ => Face(1));

        var result = await verifier.VerifyAsync(new FaceVerificationRequest(ValidCpf, ReadOnlyMemory<byte>.Empty));

        Assert.Multiple(() =>
        {
            Assert.That(result.Failure, Is.EqualTo(FaceVerificationFailureType.InvalidImage));
            Assert.That(handler.Requests, Is.Empty);
        });
    }

    [TestCase("DV040", FaceVerificationFailureType.FaceNotOnRecord)]
    [TestCase("DV041", FaceVerificationFailureType.FaceNotDetected)]
    [TestCase("DV042", FaceVerificationFailureType.InvalidImage)]
    [TestCase("DV045", FaceVerificationFailureType.LowImageQuality)]
    [TestCase("DV046", FaceVerificationFailureType.MultipleFaces)]
    [TestCase("DV999", FaceVerificationFailureType.Rejected)]
    public async Task ReturnCode_MapsToTheFailure(string code, FaceVerificationFailureType expected)
    {
        var (verifier, _) = Create(_ => Json(HttpStatusCode.UnprocessableEntity, $$"""{"code":"{{code}}","args":[],"link":""}"""));

        var result = await verifier.VerifyAsync(Request());

        Assert.Multiple(() =>
        {
            Assert.That(result.Matched, Is.False);
            Assert.That(result.Failure, Is.EqualTo(expected));
        });
    }

    [Test]
    public async Task ErrorWithoutAReturnCode_IsUnavailable()
    {
        var (verifier, _) = Create(_ => new HttpResponseMessage(HttpStatusCode.BadGateway) { Content = new StringContent("<html>Bad Gateway</html>") });

        var result = await verifier.VerifyAsync(Request());

        Assert.That(result.Failure, Is.EqualTo(FaceVerificationFailureType.Unavailable));
    }

    [Test]
    public async Task TokenEndpointFailure_IsUnavailable()
    {
        var (verifier, _) = Create(_ => Face(1), token: _ => new HttpResponseMessage(HttpStatusCode.Unauthorized));

        var result = await verifier.VerifyAsync(Request());

        Assert.Multiple(() =>
        {
            Assert.That(result.Matched, Is.False);
            Assert.That(result.Failure, Is.EqualTo(FaceVerificationFailureType.Unavailable));
        });
    }

    [Test]
    public async Task Token_IsRequestedOnceAndAgainOnlyWhenAboutToExpire()
    {
        var (verifier, handler) = Create(_ => Face(1), token: _ => Token(expiresIn: 3600));

        await verifier.VerifyAsync(Request());
        await verifier.VerifyAsync(Request());

        Assert.That(handler.Requests.Count(r => r.Uri.AbsoluteUri == TokenUrl), Is.EqualTo(1));

        _clock.Advance(TimeSpan.FromMinutes(56));
        await verifier.VerifyAsync(Request());

        Assert.That(handler.Requests.Count(r => r.Uri.AbsoluteUri == TokenUrl), Is.EqualTo(2));
    }

    [Test]
    public async Task RefusedToken_IsDiscardedSoTheNextVerificationRequestsANewOne()
    {
        var refuse = true;
        var (verifier, handler) = Create(_ => refuse ? new HttpResponseMessage(HttpStatusCode.Unauthorized) : Face(1));

        var refused = await verifier.VerifyAsync(Request());
        refuse = false;
        var accepted = await verifier.VerifyAsync(Request());

        Assert.Multiple(() =>
        {
            Assert.That(refused.Failure, Is.EqualTo(FaceVerificationFailureType.Unavailable));
            Assert.That(accepted.Matched, Is.True);
            Assert.That(handler.Requests.Count(r => r.Uri.AbsoluteUri == TokenUrl), Is.EqualTo(2));
        });
    }

    [Test]
    public async Task EnforcedLiveness_RefusesAValueThatIsNotAccepted()
    {
        var (verifier, _) = Create(_ => Face(0.99, liveness: "Fake"), acceptedLiveness: "Live");

        var result = await verifier.VerifyAsync(Request());

        Assert.Multiple(() =>
        {
            Assert.That(result.Matched, Is.False);
            Assert.That(result.Liveness, Is.EqualTo("Fake"));
            Assert.That(result.Failure, Is.EqualTo(FaceVerificationFailureType.LivenessRejected));
        });
    }

    [Test]
    public async Task EnforcedLiveness_RefusesAMissingValue()
    {
        var (verifier, _) = Create(_ => Face(0.99), acceptedLiveness: "Live");

        var result = await verifier.VerifyAsync(Request());

        Assert.That(result.Failure, Is.EqualTo(FaceVerificationFailureType.LivenessRejected));
    }

    [Test]
    public async Task EnforcedLiveness_AcceptsAListedValueIgnoringCase()
    {
        var (verifier, _) = Create(_ => Face(0.99, liveness: "LIVE"), acceptedLiveness: "Live");

        var result = await verifier.VerifyAsync(Request());

        Assert.That(result.Matched, Is.True);
    }

    [Test]
    public async Task SectionName_ChoosesWhereTheOptionsAreReadFrom()
    {
        var handler = new StubHttpMessageHandler(request => IsTokenRequest(request) ? Token() : Face(1));
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Custom:TokenUrl"] = TokenUrl,
                ["Custom:ValidateUrl"] = ValidateUrl,
                ["Custom:ConsumerKey"] = "custom-key",
                ["Custom:ConsumerSecret"] = "custom-secret"
            })
            .Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSerproFaceVerification(configuration, sectionName: "Custom");
        services.ConfigureAll<HttpClientFactoryOptions>(options =>
            options.HttpMessageHandlerBuilderActions.Add(builder => builder.PrimaryHandler = handler));

        await services.BuildServiceProvider().GetRequiredService<IFaceVerifier>().VerifyAsync(Request());

        var token = handler.Requests.Single(r => r.Uri.AbsoluteUri == TokenUrl);
        Assert.That(token.Authorization!.Parameter, Is.EqualTo(Convert.ToBase64String(Encoding.UTF8.GetBytes("custom-key:custom-secret"))));
    }

    [Test]
    public async Task Requests_CarryTheCredentialsTheTokenAndTheCapture()
    {
        var (verifier, handler) = Create(_ => Face(1));

        await verifier.VerifyAsync(Request());

        var token = handler.Requests.Single(r => r.Uri.AbsoluteUri == TokenUrl);
        var validation = handler.Requests.Single(r => r.Uri.AbsoluteUri == ValidateUrl);

        Assert.Multiple(() =>
        {
            Assert.That(token.Authorization!.Scheme, Is.EqualTo("Basic"));
            Assert.That(token.Authorization.Parameter, Is.EqualTo(Convert.ToBase64String(Encoding.UTF8.GetBytes("key:secret"))));
            Assert.That(token.Body, Is.EqualTo("grant_type=client_credentials"));

            Assert.That(validation.Authorization!.Scheme, Is.EqualTo("Bearer"));
            Assert.That(validation.Authorization.Parameter, Is.EqualTo("token-abc"));
            Assert.That(validation.Body, Does.Contain("\"cpf\":\"52998224725\""));
            Assert.That(validation.Body, Does.Contain("\"formato\":\"JPG\""));
            Assert.That(validation.Body, Does.Contain($"\"base64\":\"{Convert.ToBase64String(Image)}\""));
        });
    }
}
