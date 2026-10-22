using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NuvTools.Security.Verification.Twilio.Messages;

namespace NuvTools.Security.Verification.Twilio;

/// <summary>
/// Sends and checks one-time codes through Twilio Verify. Twilio generates, delivers and expires the
/// code; the application never holds it.
/// </summary>
/// <param name="httpClient">Client used to call the Verify API.</param>
/// <param name="options">Verify configuration.</param>
/// <param name="logger">Logger for diagnostics.</param>
public sealed class TwilioPhoneVerifier(
    HttpClient httpClient,
    IOptions<TwilioVerifyOptions> options,
    ILogger<TwilioPhoneVerifier> logger) : IPhoneVerifier
{
    private const int MinCodeLength = 4;
    private const int MaxCodeLength = 10;

    private readonly TwilioVerifyOptions _options = options.Value;

    /// <inheritdoc />
    public async Task<PhoneVerification> StartAsync(
        string phoneNumber,
        PhoneVerificationChannelType channel = PhoneVerificationChannelType.Sms,
        string? locale = null,
        CancellationToken cancellationToken = default)
    {
        // Checked here because a call to the provider is billed.
        if (!E164PhoneNumber.IsValid(phoneNumber))
            return PhoneVerification.Failed(PhoneVerificationFailureType.InvalidNumber);

        var form = new Dictionary<string, string>
        {
            ["To"] = phoneNumber,
            ["Channel"] = channel == PhoneVerificationChannelType.Call ? "call" : "sms"
        };

        if (!string.IsNullOrWhiteSpace(locale)) form["Locale"] = locale;

        var (verification, failure) = await PostAsync("Verifications", form, cancellationToken).ConfigureAwait(false);

        if (verification is null) return PhoneVerification.Failed(failure);

        return verification.Status == "pending"
            ? PhoneVerification.Success
            : Unexpected(verification.Status);
    }

    /// <inheritdoc />
    public async Task<PhoneVerification> CheckAsync(string phoneNumber, string code, CancellationToken cancellationToken = default)
    {
        if (!E164PhoneNumber.IsValid(phoneNumber))
            return PhoneVerification.Failed(PhoneVerificationFailureType.InvalidNumber);

        // A code that cannot be right is not worth a billed call, nor one of the number's attempts.
        var trimmed = code?.Trim() ?? string.Empty;

        if (trimmed.Length is < MinCodeLength or > MaxCodeLength || !trimmed.All(char.IsAsciiDigit))
            return PhoneVerification.Failed(PhoneVerificationFailureType.CodeIncorrect);

        var (check, failure) = await PostAsync(
            "VerificationCheck",
            new Dictionary<string, string> { ["To"] = phoneNumber, ["Code"] = trimmed },
            cancellationToken).ConfigureAwait(false);

        if (check is null) return PhoneVerification.Failed(failure);

        return check.Status switch
        {
            "approved" when check.Valid => PhoneVerification.Success,
            "pending" => PhoneVerification.Failed(PhoneVerificationFailureType.CodeIncorrect),
            "max_attempts_reached" => PhoneVerification.Failed(PhoneVerificationFailureType.TooManyAttempts),
            "expired" or "canceled" or "deleted" => PhoneVerification.Failed(PhoneVerificationFailureType.Expired),
            _ => Unexpected(check.Status)
        };
    }

    private async Task<(TwilioVerification? Verification, PhoneVerificationFailureType Failure)> PostAsync(
        string resource, Dictionary<string, string> form, CancellationToken cancellationToken)
    {
        if (!_options.IsConfigured)
        {
            logger.LogWarning("Twilio Verify is not configured: set the API key SID, its secret and the service SID.");
            return (null, PhoneVerificationFailureType.Unavailable);
        }

        try
        {
            var address = $"{_options.BaseUrl.TrimEnd('/')}/Services/{Uri.EscapeDataString(_options.ServiceSid)}/{resource}";

            using var message = new HttpRequestMessage(HttpMethod.Post, address)
            {
                Content = new FormUrlEncodedContent(form)
            };

            message.Headers.Authorization = new AuthenticationHeaderValue(
                "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_options.ApiKeySid}:{_options.ApiKeySecret}")));
            message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using var response = await httpClient.SendAsync(message, cancellationToken).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
                return (null, await ReadFailureAsync(response, cancellationToken).ConfigureAwait(false));

            var verification = await response.Content.ReadFromJsonAsync<TwilioVerification>(cancellationToken).ConfigureAwait(false);

            if (verification is null)
            {
                logger.LogWarning("Twilio Verify answered {Resource} with an empty body.", resource);
                return (null, PhoneVerificationFailureType.Unavailable);
            }

            return (verification, PhoneVerificationFailureType.None);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Network failure or unexpected response: nothing is sent or accepted (fail-closed).
            logger.LogWarning(ex, "Failed to call Twilio Verify ({Resource}).", resource);
            return (null, PhoneVerificationFailureType.Unavailable);
        }
    }

    private async Task<PhoneVerificationFailureType> ReadFailureAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        TwilioError? error = null;

        try
        {
            error = await response.Content.ReadFromJsonAsync<TwilioError>(cancellationToken).ConfigureAwait(false);
        }
        catch (JsonException)
        {
            // Not a Twilio error body (a proxy page, for instance): handled below as no code.
        }

        logger.LogWarning("Twilio Verify refused the request with status {StatusCode}, code {Code}: {Message}",
            (int)response.StatusCode, error?.Code, error?.Message);

        // Error codes: https://www.twilio.com/docs/api/errors
        return error?.Code switch
        {
            // Invalid parameter (the number), and a landline that cannot take a text message.
            60200 or 60205 => PhoneVerificationFailureType.InvalidNumber,
            // Too many checks of one code, too many codes to one number, too many requests.
            60202 or 60203 or 20429 => PhoneVerificationFailureType.TooManyAttempts,
            // A check with no verification pending: expired, already approved, or never started.
            20404 => PhoneVerificationFailureType.Expired,
            _ when response.StatusCode == HttpStatusCode.TooManyRequests => PhoneVerificationFailureType.TooManyAttempts,
            // Credentials refused, or Twilio itself failing: nothing the person can fix.
            _ when response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden
                   || (int)response.StatusCode >= 500 => PhoneVerificationFailureType.Unavailable,
            null => PhoneVerificationFailureType.Unavailable,
            _ => PhoneVerificationFailureType.Rejected
        };
    }

    private PhoneVerification Unexpected(string? status)
    {
        logger.LogWarning("Twilio Verify answered with the unexpected status '{Status}'.", status);
        return PhoneVerification.Failed(PhoneVerificationFailureType.Unavailable);
    }
}
