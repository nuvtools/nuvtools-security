using NuvTools.Security.Captcha;

namespace NuvTools.Security.Test.Captcha;

/// <summary>Returns a fixed verification and records how it was called.</summary>
internal sealed class StubCaptchaVerifier(CaptchaVerification verification) : ICaptchaVerifier
{
    public bool WasCalled { get; private set; }

    public string? ReceivedToken { get; private set; }

    public bool ReceivedCheckboxMode { get; private set; }

    public Task<CaptchaVerification> VerifyAsync(string? token, bool checkboxMode, CancellationToken cancellationToken = default)
    {
        WasCalled = true;
        ReceivedToken = token;
        ReceivedCheckboxMode = checkboxMode;
        return Task.FromResult(verification);
    }
}
