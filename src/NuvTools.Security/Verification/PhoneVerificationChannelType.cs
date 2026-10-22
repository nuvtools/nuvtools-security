namespace NuvTools.Security.Verification;

/// <summary>How a code reaches the phone.</summary>
public enum PhoneVerificationChannelType
{
    /// <summary>A text message.</summary>
    Sms = 0,

    /// <summary>A voice call that reads the code out.</summary>
    Call = 1
}
