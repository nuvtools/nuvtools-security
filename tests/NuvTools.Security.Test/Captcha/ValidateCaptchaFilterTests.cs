using NUnit.Framework;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using NuvTools.Security.AspNetCore.Captcha;
using NuvTools.Security.Captcha;
using NuvResult = NuvTools.Common.ResultWrapper.IResult;

namespace NuvTools.Security.Test.Captcha;

[TestFixture]
public class ValidateCaptchaFilterTests
{
    private const string AnyToken = "token-abc";

    private static ActionExecutingContext CreateContext(string? token = null, string? mode = null)
    {
        var httpContext = new DefaultHttpContext();

        if (token is not null)
            httpContext.Request.Headers[CaptchaDefaults.TokenHeader] = token;

        if (mode is not null)
            httpContext.Request.Headers[CaptchaDefaults.ModeHeader] = mode;

        var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor());

        return new ActionExecutingContext(actionContext, [], new Dictionary<string, object?>(), controller: null!);
    }

    private static (ActionExecutionDelegate Next, Func<bool> WasCalled) CreateNext(ActionExecutingContext context)
    {
        var called = false;

        Task<ActionExecutedContext> Next()
        {
            called = true;
            return Task.FromResult(new ActionExecutedContext(context, [], controller: null!));
        }

        return (Next, () => called);
    }

    private static IEnumerable<string> TitlesOf(ActionExecutingContext context)
    {
        var badRequest = context.Result as BadRequestObjectResult;
        var result = badRequest?.Value as NuvResult;
        return result?.Messages?.Select(m => m.Title ?? string.Empty) ?? [];
    }

    [Test]
    public async Task Disabled_SkipsVerificationEntirely()
    {
        var verifier = new StubCaptchaVerifier(new CaptchaVerification(false, 0));
        var filter = new ValidateCaptchaFilter(verifier, Options.Create(new CaptchaOptions { Enabled = false }));

        var context = CreateContext();
        var (next, wasCalled) = CreateNext(context);

        await filter.OnActionExecutionAsync(context, next);

        Assert.Multiple(() =>
        {
            Assert.That(wasCalled(), Is.True, "the action should run when the CAPTCHA is disabled");
            Assert.That(verifier.WasCalled, Is.False, "the verifier should not be called when disabled");
            Assert.That(context.Result, Is.Null);
        });
    }

    [Test]
    public async Task ScoreMode_ValidAndAboveThreshold_RunsAction()
    {
        var verifier = new StubCaptchaVerifier(new CaptchaVerification(true, 0.9));
        var filter = new ValidateCaptchaFilter(verifier, Options.Create(new CaptchaOptions { MinScore = 0.5 }));

        var context = CreateContext(AnyToken, CaptchaDefaults.ModeScore);
        var (next, wasCalled) = CreateNext(context);

        await filter.OnActionExecutionAsync(context, next);

        Assert.Multiple(() =>
        {
            Assert.That(wasCalled(), Is.True);
            Assert.That(context.Result, Is.Null);
            Assert.That(verifier.ReceivedCheckboxMode, Is.False);
            Assert.That(verifier.ReceivedToken, Is.EqualTo(AnyToken));
        });
    }

    [Test]
    public async Task ScoreMode_BelowThreshold_AsksForStepUp()
    {
        var verifier = new StubCaptchaVerifier(new CaptchaVerification(true, 0.1));
        var filter = new ValidateCaptchaFilter(verifier, Options.Create(new CaptchaOptions { MinScore = 0.5 }));

        var context = CreateContext(AnyToken, CaptchaDefaults.ModeScore);
        var (next, wasCalled) = CreateNext(context);

        await filter.OnActionExecutionAsync(context, next);

        Assert.Multiple(() =>
        {
            Assert.That(wasCalled(), Is.False, "the action must not run on a low score");
            Assert.That(context.Result, Is.InstanceOf<BadRequestObjectResult>());
            Assert.That(TitlesOf(context), Does.Contain(CaptchaDefaults.StepUpMarker));
            Assert.That(context.HttpContext.Response.Headers[CaptchaDefaults.StepUpHeader].ToString(), Is.EqualTo("true"));
        });
    }

    [Test]
    public async Task ScoreMode_EmptyToken_AsksForStepUpAndNeverBypasses()
    {
        // An empty token is what the client sends when the provider script fails to load.
        var verifier = new StubCaptchaVerifier(new CaptchaVerification(false, 0));
        var filter = new ValidateCaptchaFilter(verifier, Options.Create(new CaptchaOptions()));

        var context = CreateContext(token: string.Empty, mode: CaptchaDefaults.ModeScore);
        var (next, wasCalled) = CreateNext(context);

        await filter.OnActionExecutionAsync(context, next);

        Assert.Multiple(() =>
        {
            Assert.That(wasCalled(), Is.False, "an empty token must never reach the action");
            Assert.That(TitlesOf(context), Does.Contain(CaptchaDefaults.StepUpMarker));
        });
    }

    [Test]
    public async Task CheckboxMode_Valid_RunsAction()
    {
        var verifier = new StubCaptchaVerifier(new CaptchaVerification(true, 0));
        var filter = new ValidateCaptchaFilter(verifier, Options.Create(new CaptchaOptions()));

        var context = CreateContext(AnyToken, CaptchaDefaults.ModeCheckbox);
        var (next, wasCalled) = CreateNext(context);

        await filter.OnActionExecutionAsync(context, next);

        Assert.Multiple(() =>
        {
            Assert.That(wasCalled(), Is.True, "a solved checkbox only has to be valid, the score is irrelevant");
            Assert.That(verifier.ReceivedCheckboxMode, Is.True);
        });
    }

    [Test]
    public async Task CheckboxMode_Invalid_FailsWithConfiguredMessage()
    {
        const string failureMessage = "Falha na verificação de segurança.";

        var verifier = new StubCaptchaVerifier(new CaptchaVerification(false, 0));
        var filter = new ValidateCaptchaFilter(verifier, Options.Create(new CaptchaOptions { FailureMessage = failureMessage }));

        var context = CreateContext(AnyToken, CaptchaDefaults.ModeCheckbox);
        var (next, wasCalled) = CreateNext(context);

        await filter.OnActionExecutionAsync(context, next);

        Assert.Multiple(() =>
        {
            Assert.That(wasCalled(), Is.False);
            Assert.That(context.Result, Is.InstanceOf<BadRequestObjectResult>());
            Assert.That(TitlesOf(context), Does.Contain(failureMessage));
            Assert.That(TitlesOf(context), Does.Not.Contain(CaptchaDefaults.StepUpMarker),
                "a failed checkbox must not loop the client back into another step-up");
        });
    }
}
