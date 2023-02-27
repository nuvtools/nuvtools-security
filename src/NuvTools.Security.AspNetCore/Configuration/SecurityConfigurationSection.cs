namespace NuvTools.Security.AspNetCore.Configuration;

/// <summary>
/// Contains the mail configuration that should be loaded from appsettings file.
/// <para>The default section name is "NuvTools.Security"</para>
/// </summary>
public class SecurityConfigurationSection
{
    public string Issuer { get; set; }
    public string Audience { get; set; }
    public string SecretKey { get; set; }
}