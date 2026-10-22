namespace NuvTools.Security.Verification;

/// <summary>
/// Proves that a person holds a phone number: a one-time code is sent to it, and the code the person
/// types back is checked.
/// </summary>
/// <remarks>
/// <para>
/// The provider generates, sends, stores and expires the code. The application never sees it, so it
/// has nothing to store, compare or leak; it only asks whether what the person typed was right.
/// </para>
/// <para>
/// Numbers are in E.164 form (<c>+5511987654321</c>). <see cref="E164PhoneNumber"/> turns what a person
/// types into that form. Both operations fail closed: a provider that cannot be reached answers
/// <see cref="PhoneVerificationFailureType.Unavailable"/>, never success.
/// </para>
/// </remarks>
public interface IPhoneVerifier
{
    /// <summary>Sends a new code to the number, replacing any code still pending for it.</summary>
    /// <param name="phoneNumber">The number in E.164 form.</param>
    /// <param name="channel">How the code reaches the person. Defaults to a text message.</param>
    /// <param name="locale">
    /// The language of the message, as an IETF tag (<c>pt-BR</c>, <c>en</c>), or <c>null</c> for the
    /// provider's choice.
    /// </param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>Whether the code was sent, and why not when it was not.</returns>
    Task<PhoneVerification> StartAsync(
        string phoneNumber,
        PhoneVerificationChannelType channel = PhoneVerificationChannelType.Sms,
        string? locale = null,
        CancellationToken cancellationToken = default);

    /// <summary>Checks the code the person typed against the one pending for the number.</summary>
    /// <param name="phoneNumber">The number in E.164 form, as it was given to <see cref="StartAsync"/>.</param>
    /// <param name="code">What the person typed.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>
    /// <see cref="PhoneVerification.Succeeded"/> only when the code is the pending one. A code is good
    /// once: after a success the number has no code pending.
    /// </returns>
    Task<PhoneVerification> CheckAsync(string phoneNumber, string code, CancellationToken cancellationToken = default);
}
