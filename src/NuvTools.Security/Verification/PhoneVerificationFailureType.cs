namespace NuvTools.Security.Verification;

/// <summary>Why a code was not sent, or not accepted.</summary>
/// <remarks>
/// The values tell the application which message helps the person: a new code fixes
/// <see cref="Expired"/>, typing again fixes <see cref="CodeIncorrect"/>, waiting fixes
/// <see cref="TooManyAttempts"/>, and only another number fixes <see cref="InvalidNumber"/>.
/// </remarks>
public enum PhoneVerificationFailureType
{
    /// <summary>The code was sent, or accepted.</summary>
    None = 0,

    /// <summary>The number is not a valid E.164 number, or the provider cannot deliver to it.</summary>
    InvalidNumber = 1,

    /// <summary>The code is not the one pending for the number.</summary>
    CodeIncorrect = 2,

    /// <summary>
    /// No code is pending for the number: it expired, it was already used, or none was sent.
    /// </summary>
    Expired = 3,

    /// <summary>The provider refuses more codes, or more checks, for the number for now.</summary>
    TooManyAttempts = 4,

    /// <summary>The provider refused the request for a reason this contract does not name.</summary>
    Rejected = 5,

    /// <summary>
    /// The provider could not be reached or answered unexpectedly. Nothing is known about the code.
    /// </summary>
    Unavailable = 6
}
