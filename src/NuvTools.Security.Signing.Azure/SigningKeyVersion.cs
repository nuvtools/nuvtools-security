namespace NuvTools.Security.Signing.Azure;

/// <summary>
/// One usable version of the signing key.
/// </summary>
/// <param name="Version">The version's name in the vault; it becomes the key identifier.</param>
/// <param name="CreatedOn">When the vault created it.</param>
internal sealed record SigningKeyVersion(string Version, DateTimeOffset CreatedOn);
