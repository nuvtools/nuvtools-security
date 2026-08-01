using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.Options;
using NuvTools.Common.ResultWrapper;
using NuvTools.Security.Captcha;

namespace NuvTools.Security.AspNetCore.Blazor.Captcha;

/// <summary>
/// Reusable adaptive CAPTCHA (Google reCAPTCHA Enterprise) for public screens.
/// </summary>
/// <remarks>
/// Runs <b>invisible</b> by default (score key, via execute) — nothing appears on screen. When the
/// server flags the risk as high, the form calls <see cref="RequireStepUpAsync"/> and the component
/// renders the <b>checkbox</b> challenge (checkbox key) as a step-up. Driven by
/// <see cref="CaptchaOptions"/>, registered with <c>AddCaptcha</c>.
/// </remarks>
public partial class NuvCaptcha : IAsyncDisposable
{
    [Inject] private IOptions<CaptchaOptions> Options { get; set; } = default!;
    [Inject] private ICaptchaService CaptchaService { get; set; } = default!;

    /// <summary>CSS class applied to the element that hosts the checkbox widget.</summary>
    [Parameter] public string? Class { get; set; }

    /// <summary>
    /// Value returned as the token when the CAPTCHA is disabled, so the caller's checks still pass.
    /// </summary>
    private const string DisabledToken = "disabled";

    private readonly string ElementId = $"captcha-{Guid.NewGuid():N}";

    private bool _checkboxRendered;

    /// <summary>Whether verification is enabled by configuration.</summary>
    private bool Enabled => Options.Value.Enabled;

    /// <summary>Whether the component is already in checkbox (step-up) mode.</summary>
    public bool IsStepUp { get; private set; }

    /// <inheritdoc />
    protected override async Task OnAfterRenderAsync(bool firstRender)
    {
        // Renders the checkbox as soon as step-up begins — the element exists after StateHasChanged.
        if (Enabled && IsStepUp && !_checkboxRendered && !string.IsNullOrWhiteSpace(Options.Value.SiteKey))
        {
            _checkboxRendered = true;
            await CaptchaService.RenderCheckboxAsync(ElementId, Options.Value.SiteKey, Options.Value.ScoreSiteKey);
        }
    }

    /// <summary>
    /// Gets the current token and mode. Without step-up: the invisible score token. In step-up: the
    /// checkbox token. When disabled, returns a non-empty token, since the server also skips
    /// verification in that mode.
    /// </summary>
    /// <returns>The token and the mode to send in the request headers.</returns>
    public async Task<(string? Token, string Mode)> GetTokenAsync()
    {
        if (!Enabled)
            return (DisabledToken, CaptchaDefaults.ModeScore);

        if (IsStepUp)
        {
            var checkboxToken = await CaptchaService.GetCheckboxResponseAsync(ElementId);
            return (checkboxToken, CaptchaDefaults.ModeCheckbox);
        }

        var scoreToken = await CaptchaService.ExecuteAsync(Options.Value.ScoreSiteKey);
        return (scoreToken, CaptchaDefaults.ModeScore);
    }

    /// <summary>
    /// Enters checkbox mode and returns <c>true</c> when the result carries the step-up marker (low
    /// score), meaning the caller should stop and let the user solve the challenge.
    /// </summary>
    /// <param name="result">The result returned by the server call.</param>
    /// <returns><c>true</c> when the caller must wait for the user to solve the challenge.</returns>
    public async Task<bool> HandleStepUpAsync(IResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        if (!result.Succeeded && result.Messages is not null
            && result.Messages.Any(m => string.Equals(m.Title, CaptchaDefaults.StepUpMarker, StringComparison.OrdinalIgnoreCase)))
        {
            await RequireStepUpAsync();
            return true;
        }

        return false;
    }

    /// <summary>Enters step-up: renders the checkbox for the user to confirm they are human.</summary>
    public Task RequireStepUpAsync()
    {
        if (Enabled && !IsStepUp)
        {
            IsStepUp = true;
            StateHasChanged();
        }

        return Task.CompletedTask;
    }

    /// <summary>Clears the checkbox challenge for a new attempt — the token is single-use.</summary>
    public async Task ResetAsync()
    {
        if (Enabled && IsStepUp && _checkboxRendered)
            await CaptchaService.ResetCheckboxAsync(ElementId);
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        // Releases the widget entry — the id is unique per component instance.
        if (Enabled && _checkboxRendered)
        {
            try { await CaptchaService.DisposeCheckboxAsync(ElementId); } catch { /* ignore */ }
        }

        GC.SuppressFinalize(this);
    }
}
