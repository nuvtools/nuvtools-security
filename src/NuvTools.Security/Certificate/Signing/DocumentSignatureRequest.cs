namespace NuvTools.Security.Certificate.Signing;

/// <summary>A PDF to be signed.</summary>
/// <param name="Document">The PDF, which may already carry other signatures.</param>
/// <param name="Stamp">The visible mark of this signature on the document, or <c>null</c> for an invisible signature.</param>
public sealed record DocumentSignatureRequest(ReadOnlyMemory<byte> Document, SignatureStamp? Stamp = null);
