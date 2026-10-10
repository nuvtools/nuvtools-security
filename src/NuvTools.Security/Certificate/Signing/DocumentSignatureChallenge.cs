namespace NuvTools.Security.Certificate.Signing;

/// <summary>A signature the provider prepared and the client has yet to sign.</summary>
/// <param name="Token">
/// Identifies the signature on the provider. The client signs it with the chosen certificate and sends
/// it back to complete the signature.
/// </param>
public sealed record DocumentSignatureChallenge(string Token);
