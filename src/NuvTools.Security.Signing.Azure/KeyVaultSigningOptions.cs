namespace NuvTools.Security.Signing.Azure;

/// <summary>
/// Where the signing key lives and how its rotation is followed.
/// </summary>
public class KeyVaultSigningOptions
{
    /// <summary>The configuration section these options are bound from by default.</summary>
    public const string SectionName = "KeyVaultSigning";

    /// <summary>The vault's address, for example <c>https://contoso-kv.vault.azure.net/</c>.</summary>
    public string VaultUri { get; set; } = string.Empty;

    /// <summary>The name of the RSA key in the vault. Every enabled version of it is used.</summary>
    public string KeyName { get; set; } = string.Empty;

    /// <summary>
    /// How long a new version is published before it starts signing. It gives whoever validates
    /// the tokens time to learn the new key, so the first token signed with it is not refused by a
    /// validator still holding the previous key set. Defaults to one hour.
    /// </summary>
    public TimeSpan ActivationDelay { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// How long the list of versions is reused before the vault is asked again; a rotation is
    /// noticed within this time. Defaults to five minutes.
    /// </summary>
    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromMinutes(5);
}
