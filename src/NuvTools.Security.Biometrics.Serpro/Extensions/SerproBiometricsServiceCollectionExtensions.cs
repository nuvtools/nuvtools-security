using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NuvTools.Security.Biometrics.Serpro;

namespace NuvTools.Security.Biometrics.Serpro.Extensions;

/// <summary>
/// Extension methods for registering the facial verification services.
/// </summary>
public static class SerproBiometricsServiceCollectionExtensions
{
    private const int DefaultTimeoutInSeconds = 30;

    /// <summary>
    /// Binds <see cref="DatavalidOptions"/> from configuration and registers SERPRO Datavalid as the
    /// <see cref="IFaceVerifier"/>, with its own <see cref="HttpClient"/> and a cached access token.
    /// </summary>
    /// <param name="services">The service collection to add the services to.</param>
    /// <param name="configuration">Configuration holding the Datavalid section.</param>
    /// <param name="sectionName">
    /// Name of the section to bind. Defaults to <see cref="DatavalidOptions.SectionName"/>; pass the
    /// application's own when its settings already live under another name.
    /// </param>
    /// <param name="timeoutInSeconds">Timeout of each call to SERPRO. Defaults to 30 seconds.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <remarks>
    /// This is the only place a caller names the provider: everything above it depends on
    /// <see cref="IFaceVerifier"/>, so changing provider is changing this call.
    /// </remarks>
    public static IServiceCollection AddSerproFaceVerification(this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = DatavalidOptions.SectionName,
        int timeoutInSeconds = DefaultTimeoutInSeconds)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentException.ThrowIfNullOrWhiteSpace(sectionName);

        services.Configure<DatavalidOptions>(configuration.GetSection(sectionName));

        services.TryAddSingleton(TimeProvider.System);

        services.AddHttpClient(DatavalidAccessTokenProvider.HttpClientName,
            client => client.Timeout = TimeSpan.FromSeconds(timeoutInSeconds));

        services.AddSingleton<DatavalidAccessTokenProvider>();

        services.AddHttpClient<IFaceVerifier, DatavalidFaceVerifier>(
            client => client.Timeout = TimeSpan.FromSeconds(timeoutInSeconds));

        return services;
    }
}
