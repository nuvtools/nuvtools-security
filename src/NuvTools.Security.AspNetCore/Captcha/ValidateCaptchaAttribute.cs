using Microsoft.AspNetCore.Mvc;

namespace NuvTools.Security.AspNetCore.Captcha;

/// <summary>
/// Requires a valid CAPTCHA token (header <c>X-Captcha-Token</c>) to execute the action or controller.
/// </summary>
/// <remarks>
/// Apply it to anonymous or public endpoints that could be targeted by automated access, bulk
/// submission or brute force. Verification is skipped when the CAPTCHA is disabled in configuration.
/// </remarks>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = false)]
public sealed class ValidateCaptchaAttribute() : TypeFilterAttribute(typeof(ValidateCaptchaFilter));
