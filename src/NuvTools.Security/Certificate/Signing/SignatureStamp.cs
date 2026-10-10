namespace NuvTools.Security.Certificate.Signing;

/// <summary>The visible mark a signature leaves on the document.</summary>
/// <param name="Image">The image of the stamp. What it shows is the application's choice: the provider only places it.</param>
/// <param name="ImageContentType">MIME type of <paramref name="Image"/>, for example <c>image/png</c>.</param>
/// <param name="Placement">Where on the document the stamp goes.</param>
public sealed record SignatureStamp(ReadOnlyMemory<byte> Image, string ImageContentType, SignatureStampPlacement Placement);
