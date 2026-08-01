using Microsoft.JSInterop;

namespace NuvTools.Security.AspNetCore.Blazor.Captcha;

/// <summary>
/// Provides JavaScript interop for the adaptive CAPTCHA (Google reCAPTCHA Enterprise).
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="CaptchaService"/> class.
/// </remarks>
/// <param name="jsRuntime">The JavaScript runtime for interop operations.</param>
public sealed class CaptchaService(IJSRuntime jsRuntime) : ICaptchaService
{
    private const string ModulePath = "./_content/NuvTools.Security.AspNetCore.Blazor/captcha.js";

    private IJSObjectReference? _module;

    private async ValueTask<IJSObjectReference> GetModuleAsync(CancellationToken cancellationToken)
    {
        return _module ??= await jsRuntime.InvokeAsync<IJSObjectReference>(
            "import", cancellationToken, ModulePath).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask<string?> ExecuteAsync(string scoreKey, string action = "submit",
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scoreKey);

        var module = await GetModuleAsync(cancellationToken).ConfigureAwait(false);
        return await module.InvokeAsync<string?>("execute", cancellationToken, scoreKey, action).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask RenderCheckboxAsync(string elementId, string checkboxKey, string scoreKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(elementId);
        ArgumentException.ThrowIfNullOrWhiteSpace(checkboxKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(scoreKey);

        var module = await GetModuleAsync(cancellationToken).ConfigureAwait(false);
        await module.InvokeVoidAsync("renderCheckbox", cancellationToken, elementId, checkboxKey, scoreKey).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask<string?> GetCheckboxResponseAsync(string elementId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(elementId);

        var module = await GetModuleAsync(cancellationToken).ConfigureAwait(false);
        return await module.InvokeAsync<string?>("getCheckboxResponse", cancellationToken, elementId).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask ResetCheckboxAsync(string elementId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(elementId);

        var module = await GetModuleAsync(cancellationToken).ConfigureAwait(false);
        await module.InvokeVoidAsync("resetCheckbox", cancellationToken, elementId).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask DisposeCheckboxAsync(string elementId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(elementId);

        var module = await GetModuleAsync(cancellationToken).ConfigureAwait(false);
        await module.InvokeVoidAsync("disposeCheckbox", cancellationToken, elementId).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_module is not null)
        {
            await _module.DisposeAsync().ConfigureAwait(false);
            _module = null;
        }
    }
}
