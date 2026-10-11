using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace NuvTools.Security.Signing.Azure.Extensions;

/// <summary>
/// Extension methods for registering the Azure Key Vault signing keys.
/// </summary>
public static class KeyVaultSigningServiceCollectionExtensions
{
    /// <summary>
    /// Binds <see cref="KeyVaultSigningOptions"/> from configuration and registers Azure Key Vault as
    /// the <see cref="ISigningKeyProvider"/>.
    /// </summary>
    /// <param name="services">The service collection to add the services to.</param>
    /// <param name="configuration">Configuration holding the signing section.</param>
    /// <param name="sectionName">
    /// Name of the section to bind. Defaults to <see cref="KeyVaultSigningOptions.SectionName"/>; pass
    /// the application's own when its settings already live under another name.
    /// </param>
    /// <param name="credential">
    /// The identity to reach the vault with. Defaults to <see cref="DefaultAzureCredential"/>, which
    /// resolves a managed identity when deployed and the developer's own login on a workstation.
    /// </param>
    /// <returns>The service collection for chaining.</returns>
    /// <remarks>
    /// This is the only place a caller names the key store: everything above it depends on
    /// <see cref="ISigningKeyProvider"/>, so changing store is changing this call.
    /// </remarks>
    public static IServiceCollection AddKeyVaultSigningKeys(this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = KeyVaultSigningOptions.SectionName,
        TokenCredential? credential = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentException.ThrowIfNullOrWhiteSpace(sectionName);

        services.Configure<KeyVaultSigningOptions>(configuration.GetSection(sectionName));

        services.TryAddSingleton(TimeProvider.System);

        services.AddSingleton<ISigningKeyProvider>(provider =>
        {
            var options = provider.GetRequiredService<IOptions<KeyVaultSigningOptions>>();

            if (!Uri.TryCreate(options.Value.VaultUri, UriKind.Absolute, out var vault))
                throw new InvalidOperationException(
                    $"'{sectionName}:{nameof(KeyVaultSigningOptions.VaultUri)}' is required and must be the vault's absolute address.");

            var identity = credential ?? new DefaultAzureCredential();

            return new KeyVaultSigningKeyProvider(
                new KeyClient(vault, identity),
                identity,
                options,
                provider.GetRequiredService<TimeProvider>(),
                provider.GetRequiredService<ILogger<KeyVaultSigningKeyProvider>>());
        });

        return services;
    }
}
