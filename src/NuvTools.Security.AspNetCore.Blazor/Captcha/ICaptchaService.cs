namespace NuvTools.Security.AspNetCore.Blazor.Captcha;

/// <summary>
/// Provides JavaScript interop for the adaptive CAPTCHA (Google reCAPTCHA Enterprise).
/// </summary>
/// <remarks>
/// When the provider script cannot be loaded, the token-producing members return an empty string
/// rather than failing. The server treats an empty token as invalid, so the outcome is fail-closed.
/// </remarks>
public interface ICaptchaService : IAsyncDisposable
{
    /// <summary>
    /// Produces an invisible (score) token. Nothing is shown to the user.
    /// </summary>
    /// <param name="scoreKey">Site key of the score type.</param>
    /// <param name="action">Action name recorded on the assessment. Defaults to <c>submit</c>.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>The token, or an empty string when the provider is unavailable.</returns>
    ValueTask<string?> ExecuteAsync(string scoreKey, string action = "submit", CancellationToken cancellationToken = default);

    /// <summary>
    /// Renders the "I'm not a robot" checkbox into the given element, as the step-up challenge.
    /// </summary>
    /// <param name="elementId">Id of the element that hosts the widget.</param>
    /// <param name="checkboxKey">Site key of the checkbox type.</param>
    /// <param name="scoreKey">Site key of the score type, used to load the provider script.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    ValueTask RenderCheckboxAsync(string elementId, string checkboxKey, string scoreKey, CancellationToken cancellationToken = default);

    /// <summary>
    /// Reads the token produced by the checkbox widget.
    /// </summary>
    /// <param name="elementId">Id of the element hosting the widget.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>The token, or an empty string when the challenge was not solved.</returns>
    ValueTask<string?> GetCheckboxResponseAsync(string elementId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Clears the checkbox challenge so the user can try again — the token is single-use.
    /// </summary>
    /// <param name="elementId">Id of the element hosting the widget.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    ValueTask ResetCheckboxAsync(string elementId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Releases the widget bookkeeping for the element. Call it when the host component is disposed.
    /// </summary>
    /// <param name="elementId">Id of the element hosting the widget.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    ValueTask DisposeCheckboxAsync(string elementId, CancellationToken cancellationToken = default);
}
