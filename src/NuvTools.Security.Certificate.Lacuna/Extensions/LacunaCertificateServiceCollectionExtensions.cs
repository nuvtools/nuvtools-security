using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using NuvTools.Security.Certificate.Lacuna;

namespace NuvTools.Security.Certificate.Lacuna.Extensions;

/// <summary>
/// Extension methods for registering the certificate authentication services.
/// </summary>
public static class LacunaCertificateServiceCollectionExtensions
{
    /// <summary>
    /// Binds <see cref="RestPkiOptions"/> from configuration and registers Lacuna REST PKI as the
    /// <see cref="ICertificateAuthenticator"/>.
    /// </summary>
    /// <param name="services">The service collection to add the services to.</param>
    /// <param name="configuration">Configuration holding the REST PKI section.</param>
    /// <param name="sectionName">
    /// Name of the section to bind. Defaults to <see cref="RestPkiOptions.SectionName"/>; pass the
    /// application's own when its settings already live under another name.
    /// </param>
    /// <returns>The service collection for chaining.</returns>
    /// <remarks>
    /// This is the only place a caller names the provider: everything above it depends on
    /// <see cref="ICertificateAuthenticator"/>, so changing provider is changing this call.
    /// </remarks>
    public static IServiceCollection AddLacunaCertificateAuthentication(this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = RestPkiOptions.SectionName)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentException.ThrowIfNullOrWhiteSpace(sectionName);

        services.Configure<RestPkiOptions>(configuration.GetSection(sectionName));

        services.AddSingleton<ICertificateAuthenticator, RestPkiCertificateAuthenticator>();

        return services;
    }
}
