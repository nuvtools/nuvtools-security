using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;
using NuvTools.Security.Captcha;
using NuvTools.Common.ResultWrapper;

namespace NuvTools.Security.AspNetCore.Captcha;

/// <summary>
/// Adaptive CAPTCHA action filter (reCAPTCHA Enterprise).
/// </summary>
/// <remarks>
/// Default flow: the client sends a <b>score</b> token (invisible) in
/// <see cref="CaptchaDefaults.TokenHeader"/> with <see cref="CaptchaDefaults.ModeHeader"/> set to
/// <see cref="CaptchaDefaults.ModeScore"/>. If the score falls below
/// <see cref="CaptchaOptions.MinScore"/>, the filter answers asking for a <b>step-up</b>
/// (<see cref="CaptchaDefaults.StepUpMarker"/>) and the client resubmits with the checkbox token
/// (<see cref="CaptchaDefaults.ModeCheckbox"/>). Verification is skipped when the CAPTCHA is disabled.
/// </remarks>
/// <param name="verifier">Verifier that creates the assessment against the provider.</param>
/// <param name="options">CAPTCHA configuration.</param>
public sealed class ValidateCaptchaFilter(
    ICaptchaVerifier verifier,
    IOptions<CaptchaOptions> options) : IAsyncActionFilter
{
    /// <inheritdoc />
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        var opts = options.Value;
        if (!opts.Enabled)
        {
            await next().ConfigureAwait(false);
            return;
        }

        var token = context.HttpContext.Request.Headers[CaptchaDefaults.TokenHeader].ToString();
        var checkboxMode = string.Equals(
            context.HttpContext.Request.Headers[CaptchaDefaults.ModeHeader].ToString(),
            CaptchaDefaults.ModeCheckbox,
            StringComparison.OrdinalIgnoreCase);

        var verification = await verifier.VerifyAsync(token, checkboxMode, context.HttpContext.RequestAborted).ConfigureAwait(false);

        if (checkboxMode)
        {
            // Step-up: the user already solved the checkbox — it just has to be valid.
            if (verification.Valid)
            {
                await next().ConfigureAwait(false);
                return;
            }

            context.Result = new BadRequestObjectResult(Result.Fail(opts.FailureMessage));
            return;
        }

        // Score mode (invisible): passes through when valid and scoring high enough.
        if (verification.Valid && verification.Score >= opts.MinScore)
        {
            await next().ConfigureAwait(false);
            return;
        }

        // Low score, or an invalid score token: ask for the checkbox step-up.
        context.HttpContext.Response.Headers[CaptchaDefaults.StepUpHeader] = "true";
        context.Result = new BadRequestObjectResult(Result.Fail(CaptchaDefaults.StepUpMarker));
    }
}
