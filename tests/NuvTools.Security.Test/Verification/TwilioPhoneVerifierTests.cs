using System.Net;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using NuvTools.Security.Test.Biometrics;
using NuvTools.Security.Verification;
using NuvTools.Security.Verification.Twilio.Extensions;
using NUnit.Framework;

namespace NuvTools.Security.Test.Verification;

[TestFixture]
public class TwilioPhoneVerifierTests
{
    private const string BaseUrl = "https://twilio.test/v2/";
    private const string Number = "+5511987654321";

    private static HttpResponseMessage Json(HttpStatusCode status, string body)
        => new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static HttpResponseMessage Verification(string status, bool valid = false)
        => Json(HttpStatusCode.OK, $$"""{"sid":"VE1","status":"{{status}}","valid":{{(valid ? "true" : "false")}}}""");

    private static HttpResponseMessage Error(HttpStatusCode status, int code)
        => Json(status, $$"""{"code":{{code}},"message":"refused","status":{{(int)status}}}""");

    private static (IPhoneVerifier Verifier, StubHttpMessageHandler Handler) Create(
        Func<HttpRequestMessage, HttpResponseMessage> respond, bool configured = true)
    {
        var settings = new Dictionary<string, string?> { ["TwilioVerify:BaseUrl"] = BaseUrl };

        if (configured)
        {
            settings["TwilioVerify:ApiKeySid"] = "SKkey";
            settings["TwilioVerify:ApiKeySecret"] = "secret";
            settings["TwilioVerify:ServiceSid"] = "VAservice";
        }

        var handler = new StubHttpMessageHandler(respond);

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddTwilioPhoneVerification(new ConfigurationBuilder().AddInMemoryCollection(settings).Build());
        services.ConfigureAll<HttpClientFactoryOptions>(options =>
            options.HttpMessageHandlerBuilderActions.Add(builder => builder.PrimaryHandler = handler));

        return (services.BuildServiceProvider().GetRequiredService<IPhoneVerifier>(), handler);
    }

    [Test]
    public async Task Start_SendsATextMessage_WithTheApiKey()
    {
        var (verifier, handler) = Create(_ => Verification("pending"));

        var result = await verifier.StartAsync(Number, locale: "pt-BR");

        Assert.That(result.Succeeded, Is.True);

        var sent = handler.Requests.Single();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(sent.Uri.AbsoluteUri, Is.EqualTo("https://twilio.test/v2/Services/VAservice/Verifications"));
            Assert.That(sent.Authorization?.Scheme, Is.EqualTo("Basic"));
            Assert.That(Encoding.UTF8.GetString(Convert.FromBase64String(sent.Authorization!.Parameter!)), Is.EqualTo("SKkey:secret"));
            Assert.That(sent.Body, Does.Contain("To=%2B5511987654321").And.Contain("Channel=sms").And.Contain("Locale=pt-BR"));
        }
    }

    [Test]
    public async Task Start_ByCall_AsksForAVoiceCall()
    {
        var (verifier, handler) = Create(_ => Verification("pending"));

        await verifier.StartAsync(Number, PhoneVerificationChannelType.Call);

        Assert.That(handler.Requests.Single().Body, Does.Contain("Channel=call"));
    }

    [Test]
    public async Task Start_WithANumberNotInE164_NeverCallsTwilio()
    {
        var (verifier, handler) = Create(_ => Verification("pending"));

        var result = await verifier.StartAsync("11987654321");

        Assert.That(result.Failure, Is.EqualTo(PhoneVerificationFailureType.InvalidNumber));
        Assert.That(handler.Requests, Is.Empty);
    }

    [TestCase(60200, PhoneVerificationFailureType.InvalidNumber)]
    [TestCase(60205, PhoneVerificationFailureType.InvalidNumber)]
    [TestCase(60203, PhoneVerificationFailureType.TooManyAttempts)]
    [TestCase(60410, PhoneVerificationFailureType.Rejected)]
    public async Task Start_TwilioErrors_AreNamed(int code, PhoneVerificationFailureType expected)
    {
        var (verifier, _) = Create(_ => Error(HttpStatusCode.BadRequest, code));

        var result = await verifier.StartAsync(Number);

        Assert.That(result.Failure, Is.EqualTo(expected));
    }

    [Test]
    public async Task Check_TheRightCode_IsApproved()
    {
        var (verifier, handler) = Create(_ => Verification("approved", valid: true));

        var result = await verifier.CheckAsync(Number, " 123456 ");

        Assert.That(result.Succeeded, Is.True);

        var sent = handler.Requests.Single();

        Assert.That(sent.Uri.AbsoluteUri, Is.EqualTo("https://twilio.test/v2/Services/VAservice/VerificationCheck"));
        Assert.That(sent.Body, Does.Contain("Code=123456"));
    }

    [Test]
    public async Task Check_AWrongCode_IsIncorrect()
    {
        var (verifier, _) = Create(_ => Verification("pending"));

        var result = await verifier.CheckAsync(Number, "000000");

        Assert.That(result.Failure, Is.EqualTo(PhoneVerificationFailureType.CodeIncorrect));
    }

    [TestCase("")]
    [TestCase("12")]
    [TestCase("12a456")]
    public async Task Check_ACodeThatCannotBeRight_NeverCallsTwilio(string code)
    {
        var (verifier, handler) = Create(_ => Verification("approved", valid: true));

        var result = await verifier.CheckAsync(Number, code);

        Assert.That(result.Failure, Is.EqualTo(PhoneVerificationFailureType.CodeIncorrect));
        Assert.That(handler.Requests, Is.Empty);
    }

    [Test]
    public async Task Check_WithNoCodePending_IsExpired()
    {
        var (verifier, _) = Create(_ => Error(HttpStatusCode.NotFound, 20404));

        var result = await verifier.CheckAsync(Number, "123456");

        Assert.That(result.Failure, Is.EqualTo(PhoneVerificationFailureType.Expired));
    }

    [Test]
    public async Task Check_TooManyTries_IsTooManyAttempts()
    {
        var (verifier, _) = Create(_ => Error(HttpStatusCode.TooManyRequests, 60202));

        var result = await verifier.CheckAsync(Number, "123456");

        Assert.That(result.Failure, Is.EqualTo(PhoneVerificationFailureType.TooManyAttempts));
    }

    [Test]
    public async Task RefusedCredentials_AreUnavailable_NeverApproved()
    {
        var (verifier, _) = Create(_ => Error(HttpStatusCode.Unauthorized, 20003));

        var result = await verifier.CheckAsync(Number, "123456");

        Assert.That(result.Failure, Is.EqualTo(PhoneVerificationFailureType.Unavailable));
    }

    [Test]
    public async Task ANetworkFailure_IsUnavailable()
    {
        var (verifier, _) = Create(_ => throw new HttpRequestException("down"));

        var result = await verifier.StartAsync(Number);

        Assert.That(result.Failure, Is.EqualTo(PhoneVerificationFailureType.Unavailable));
    }

    [Test]
    public async Task Unconfigured_IsUnavailable_WithoutCallingTwilio()
    {
        var (verifier, handler) = Create(_ => Verification("approved", valid: true), configured: false);

        var result = await verifier.CheckAsync(Number, "123456");

        Assert.That(result.Failure, Is.EqualTo(PhoneVerificationFailureType.Unavailable));
        Assert.That(handler.Requests, Is.Empty);
    }
}
