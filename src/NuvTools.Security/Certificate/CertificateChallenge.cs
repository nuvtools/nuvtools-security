namespace NuvTools.Security.Certificate;

/// <summary>A certificate authentication the provider opened and the client has yet to sign.</summary>
/// <param name="Token">
/// Identifies the authentication on the provider. The client signs it with the chosen certificate and
/// sends it back to complete the sign-in.
/// </param>
public sealed record CertificateChallenge(string Token);
