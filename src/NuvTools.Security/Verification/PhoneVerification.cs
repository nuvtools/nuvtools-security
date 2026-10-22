namespace NuvTools.Security.Verification;

/// <summary>What became of sending a code to a phone number, or of checking one.</summary>
/// <param name="Succeeded">Whether the code was sent, or whether the code checked was the right one.</param>
/// <param name="Failure">Why not, or <see cref="PhoneVerificationFailureType.None"/>.</param>
public sealed record PhoneVerification(bool Succeeded, PhoneVerificationFailureType Failure)
{
    /// <summary>A code sent, or a code accepted.</summary>
    public static PhoneVerification Success { get; } = new(true, PhoneVerificationFailureType.None);

    /// <summary>Creates a failed result.</summary>
    /// <param name="failure">Why it failed.</param>
    public static PhoneVerification Failed(PhoneVerificationFailureType failure)
        => new(false, failure);
}
