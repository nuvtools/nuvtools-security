namespace NuvTools.Security.AspNetCore.Configuration;

/// <summary>
/// Contains the mail configuration that should be loaded from appsettings file.
/// <para>The default section name is "NuvTools.Security"</para>
/// </summary>
public class SecurityConfigurationSection
{
    public required string Issuer { get; set; }
    public required string Audience { get; set; }
    public required string SecretKey { get; set; }
}