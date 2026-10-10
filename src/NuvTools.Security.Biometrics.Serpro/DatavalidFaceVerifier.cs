using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NuvTools.Common.Strings;
using NuvTools.Security.Biometrics.Serpro.Messages;
using NuvTools.Validation.Brazil;

namespace NuvTools.Security.Biometrics.Serpro;

/// <summary>
/// Verifies a captured face through SERPRO Datavalid, which compares it with the face on government
/// record for the CPF. The credentials and the token never leave the server.
/// </summary>
/// <param name="httpClient">Client used to call the validation endpoint.</param>
/// <param name="tokenProvider">Source of the gateway's access token.</param>
/// <param name="options">Datavalid configuration.</param>
/// <param name="logger">Logger for diagnostics.</param>
public sealed class DatavalidFaceVerifier(
    HttpClient httpClient,
    DatavalidAccessTokenProvider tokenProvider,
    IOptions<DatavalidOptions> options,
    ILogger<DatavalidFaceVerifier> logger) : IFaceVerifier
{
    private readonly DatavalidOptions _options = options.Value;

    /// <inheritdoc />
    public async Task<FaceVerification> VerifyAsync(FaceVerificationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Neither check needs the provider, and a call to it is billed.
        var cpf = request.Cpf?.GetNumbersOnly() ?? string.Empty;

        if (!cpf.IsCPF())
            return FaceVerification.Failed(FaceVerificationFailureType.InvalidDocument);

        if (request.Image.IsEmpty)
            return FaceVerification.Failed(FaceVerificationFailureType.InvalidImage);

        try
        {
            var token = await tokenProvider.GetAsync(cancellationToken).ConfigureAwait(false);

            using var message = new HttpRequestMessage(HttpMethod.Post, _options.ValidateUrl)
            {
                Content = JsonContent.Create(CreateBody(cpf, request))
            };

            message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using var response = await httpClient.SendAsync(message, cancellationToken).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                tokenProvider.Invalidate();
                logger.LogWarning("Datavalid refused the access token. It was discarded and the next verification requests a new one.");
                return FaceVerification.Failed(FaceVerificationFailureType.Unavailable);
            }

            if (!response.IsSuccessStatusCode)
                return FaceVerification.Failed(await ReadFailureAsync(response, cancellationToken).ConfigureAwait(false));

            var result = await response.Content.ReadFromJsonAsync<DatavalidResponse>(cancellationToken).ConfigureAwait(false);

            return Decide(result?.Face);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Network failure or unexpected response: deny access (fail-closed) and log for diagnostics.
            logger.LogWarning(ex, "Failed to verify the face against Datavalid.");
            return FaceVerification.Failed(FaceVerificationFailureType.Unavailable);
        }
    }

    private static DatavalidRequest CreateBody(string cpf, FaceVerificationRequest request)
        => new()
        {
            Cpf = cpf,
            Validation = new DatavalidValidation
            {
                Face = new DatavalidFaceImage
                {
                    Format = request.Format == FaceImageFormatType.Png ? "PNG" : "JPG",
                    Base64 = Convert.ToBase64String(request.Image.Span)
                }
            }
        };

    private FaceVerification Decide(DatavalidFaceResult? face)
    {
        if (face is null)
        {
            logger.LogWarning("Datavalid answered without a facial result.");
            return FaceVerification.Failed(FaceVerificationFailureType.Unavailable);
        }

        if (!face.Available)
            return FaceVerification.Failed(FaceVerificationFailureType.FaceNotOnRecord);

        var liveness = string.IsNullOrWhiteSpace(face.Liveness) ? null : face.Liveness;

        if (_options.AcceptedLiveness.Count > 0 && !_options.AcceptedLiveness.Contains(liveness ?? string.Empty, StringComparer.OrdinalIgnoreCase))
        {
            logger.LogInformation("Face refused: liveness '{Liveness}' is not accepted (similarity {Similarity}).", liveness, face.Similarity);
            return new FaceVerification(false, face.Similarity, liveness, FaceVerificationFailureType.LivenessRejected);
        }

        if (face.Similarity < _options.MinSimilarity)
        {
            logger.LogInformation("Face refused: similarity {Similarity} is below the minimum {MinSimilarity} (probability '{Probability}', liveness '{Liveness}').",
                face.Similarity, _options.MinSimilarity, face.Probability, liveness);
            return new FaceVerification(false, face.Similarity, liveness, FaceVerificationFailureType.NotMatched);
        }

        logger.LogInformation("Face accepted: similarity {Similarity} (probability '{Probability}', liveness '{Liveness}').",
            face.Similarity, face.Probability, liveness);

        return new FaceVerification(true, face.Similarity, liveness, FaceVerificationFailureType.None);
    }

    private async Task<FaceVerificationFailureType> ReadFailureAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        string? code = null;

        try
        {
            code = (await response.Content.ReadFromJsonAsync<DatavalidError>(cancellationToken).ConfigureAwait(false))?.Code;
        }
        catch (JsonException)
        {
            // Not a Datavalid error body (a gateway page, for instance): handled below as no code.
        }

        logger.LogWarning("Datavalid refused the verification with status {StatusCode} and code '{Code}'.", (int)response.StatusCode, code);

        // Return codes: https://apicenter.estaleiro.serpro.gov.br/documentacao/datavalid/codigos_retorno/
        return code switch
        {
            "DV040" => FaceVerificationFailureType.FaceNotOnRecord,
            "DV041" => FaceVerificationFailureType.FaceNotDetected,
            "DV045" => FaceVerificationFailureType.LowImageQuality,
            "DV046" => FaceVerificationFailureType.MultipleFaces,
            "DV042" or "DV043" or "DV044" or "DV047" => FaceVerificationFailureType.InvalidImage,
            null or "" => FaceVerificationFailureType.Unavailable,
            _ => FaceVerificationFailureType.Rejected
        };
    }
}
