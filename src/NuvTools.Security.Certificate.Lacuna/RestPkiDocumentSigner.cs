using Lacuna.RestPki.Api;
using Lacuna.RestPki.Api.PadesSignature;
using Lacuna.RestPki.Client;
using Microsoft.Extensions.Options;
using NuvTools.Security.Certificate.Signing;

namespace NuvTools.Security.Certificate.Lacuna;

/// <summary>
/// Signs PDFs (PAdES) through Lacuna REST PKI. The client signs the challenge in the browser with Web
/// PKI (<c>signWithRestPki</c>); reading certificates, preparing the document and completing the
/// signature all happen on the service, so no key or licence is kept locally.
/// </summary>
/// <param name="options">REST PKI configuration.</param>
public sealed class RestPkiDocumentSigner(IOptions<RestPkiOptions> options) : IDocumentSigner
{
    private readonly RestPkiClient _client = new(options.Value.Endpoint, options.Value.AccessToken ?? string.Empty);
    private readonly Guid _securityContextId = options.Value.GetSecurityContextId();
    private readonly Guid _signaturePolicyId = options.Value.GetPadesSignaturePolicyId();

    /// <inheritdoc />
    public async Task<CertificateDetails> ReadCertificateAsync(ReadOnlyMemory<byte> certificate, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var explorer = new CertificateExplorer(_client)
        {
            Certificate = certificate.ToArray(),
            Validate = false
        };

        var opened = await explorer.OpenAsync().ConfigureAwait(false);

        return RestPkiCertificateReader.ToDetails(opened.Certificate);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<CertificateDetails>> GetSignersAsync(ReadOnlyMemory<byte> signedDocument, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var explorer = new PadesSignatureExplorer(_client) { Validate = false };
        explorer.SetSignatureFile(signedDocument.ToArray());

        var signature = await explorer.OpenAsync().ConfigureAwait(false);

        return [.. signature.Signers
            .Where(signer => !signer.IsDocumentTimestamp && signer.Certificate is not null)
            .Select(signer => RestPkiCertificateReader.ToDetails(signer.Certificate))];
    }

    /// <inheritdoc />
    public async Task<DocumentSignatureChallenge> StartAsync(DocumentSignatureRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        var starter = new PadesSignatureStarter(_client)
        {
            SignaturePolicyId = _signaturePolicyId,
            SecurityContextId = _securityContextId,
            MeasurementUnits = PadesMeasurementUnits.Centimeters
        };

        if (request.Stamp is not null)
            starter.VisualRepresentation = ToVisualRepresentation(request.Stamp);

        starter.SetPdfToSign(request.Document.ToArray());

        var token = await starter.StartWithWebPkiAsync().ConfigureAwait(false);

        return new DocumentSignatureChallenge(token);
    }

    /// <inheritdoc />
    public async Task<SignedDocument> CompleteAsync(string token, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        cancellationToken.ThrowIfCancellationRequested();

        var finisher = new PadesSignatureFinisher2(_client) { Token = token };
        var result = await finisher.FinishAsync().ConfigureAwait(false);

        return new SignedDocument(result.GetContent(), RestPkiCertificateReader.ToDetails(result.Certificate));
    }

    private static PadesVisualRepresentation ToVisualRepresentation(SignatureStamp stamp)
    {
        var placement = stamp.Placement;

        return new PadesVisualRepresentation
        {
            // REST PKI refuses an appearance made of an image alone (it answers 500), so a single
            // space, which shows nothing, stands in for the text it requires.
            Text = new PadesVisualText
            {
                Text = " ",
                FontSize = 6,
                HorizontalAlign = PadesTextHorizontalAlign.Left,
                Container = new PadesVisualRectangle { Left = 0.1, Top = 0.1, Right = 0.1, Bottom = 0.1 }
            },
            Image = new PadesVisualImage(stamp.Image.ToArray(), stamp.ImageContentType)
            {
                Opacity = 100,
                HorizontalAlign = PadesHorizontalAlign.Center,
                VerticalAlign = PadesVerticalAlign.Center
            },
            // Stacks the stamps inside the area. On a co-signature REST PKI places the new stamp after
            // the ones already there.
            Position = new PadesVisualAutoPositioning
            {
                PageNumber = placement.PageNumber,
                Container = new PadesVisualRectangle
                {
                    Left = placement.Area.Left,
                    Top = placement.Area.Top,
                    Right = placement.Area.Right,
                    Bottom = placement.Area.Bottom
                },
                SignatureRectangleSize = new PadesSize { Width = placement.Width, Height = placement.Height },
                RowSpacing = placement.RowSpacing,
                HorizontalDirection = AutoPositioningHorizontalDirections.LeftToRight,
                VerticalDirection = AutoPositioningVerticalDirections.TopDown
            }
        };
    }
}
