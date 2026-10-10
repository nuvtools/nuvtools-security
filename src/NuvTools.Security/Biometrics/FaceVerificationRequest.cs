namespace NuvTools.Security.Biometrics;

/// <summary>A captured face to compare with the one on record for a person.</summary>
/// <param name="Cpf">
/// CPF of the person the face should belong to, formatted or not. Take it from the account being
/// signed in to, on the server — not from what the client typed next to the capture.
/// </param>
/// <param name="Image">The captured image, as the raw bytes of the file.</param>
/// <param name="Format">Format of <paramref name="Image"/>.</param>
public sealed record FaceVerificationRequest(string Cpf, ReadOnlyMemory<byte> Image, FaceImageFormatType Format = FaceImageFormatType.Jpeg);
