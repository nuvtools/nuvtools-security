using Lacuna.RestPki.Client;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NuvTools.Common.Strings;

namespace NuvTools.Security.Certificate.Lacuna;

/// <summary>
/// Authenticates a certificate through Lacuna REST PKI. The client signs the challenge in the browser
/// with Web PKI (<c>signWithRestPki</c>); the service validates possession of the private key and the
/// trust chain, and the subject is read from the certificate it validated.
/// </summary>
/// <param name="options">REST PKI configuration.</param>
/// <param name="logger">Logger for diagnostics.</param>
public sealed class RestPkiCertificateAuthenticator(
    IOptions<RestPkiOptions> options,
    ILogger<RestPkiCertificateAuthenticator> logger) : ICertificateAuthenticator
{
    private readonly RestPkiClient _client = new(options.Value.Endpoint, options.Value.AccessToken ?? string.Empty);
    private readonly Guid _securityContextId = options.Value.GetSecurityContextId();

    /// <inheritdoc />
    public async Task<CertificateChallenge> StartAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var token = await _client.GetAuthentication().StartWithWebPkiAsync(_securityContextId).ConfigureAwait(false);

        return new CertificateChallenge(token);
    }

    /// <inheritdoc />
    public async Task<CertificateAuthentication> CompleteAsync(string? token, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
            return CertificateAuthentication.Failed(CertificateFailureType.Rejected);

        cancellationToken.ThrowIfCancellationRequested();

        var authentication = _client.GetAuthentication();

        try
        {
            var validation = await authentication.CompleteWithWebPkiAsync(token).ConfigureAwait(false);

            if (!validation.IsValid)
            {
                logger.LogWarning("Certificate rejected by REST PKI. {Validation}", validation.ToString());
                return CertificateAuthentication.Failed(CertificateFailureType.Rejected);
            }

            return CertificateAuthentication.Succeeded(ReadSubject(authentication.GetCertificate()));
        }
        catch (Exception ex)
        {
            // Network failure, unknown token or unexpected response: deny access (fail-closed) and log for diagnostics.
            logger.LogWarning(ex, "Failed to complete the certificate authentication against REST PKI.");
            return CertificateAuthentication.Failed(CertificateFailureType.Unavailable);
        }
    }

    private static CertificateSubject ReadSubject(PKCertificate certificate)
        => new(
            certificate.SubjectName?.CommonName,
            NullIfBlank(certificate.EmailAddress),
            DigitsOrNull(certificate.PkiBrazil?.Cpf),
            DigitsOrNull(certificate.PkiBrazil?.Cnpj),
            NullIfBlank(certificate.PkiBrazil?.CompanyName));

    private static string? NullIfBlank(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value;

    private static string? DigitsOrNull(string? value)
        => NullIfBlank(value?.GetNumbersOnly());
}
