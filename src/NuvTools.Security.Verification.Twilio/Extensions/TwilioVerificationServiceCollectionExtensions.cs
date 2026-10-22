using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace NuvTools.Security.Verification.Twilio.Extensions;

/// <summary>
/// Extension methods for registering the phone verification services.
/// </summary>
public static class TwilioVerificationServiceCollectionExtensions
{
    private const int DefaultTimeoutInSeconds = 30;

    /// <summary>
    /// Binds <see cref="TwilioVerifyOptions"/> from configuration and registers Twilio Verify as the
    /// <see cref="IPhoneVerifier"/>, with its own <see cref="HttpClient"/>.
    /// </summary>
    /// <param name="services">The service collection to add the services to.</param>
    /// <param name="configuration">Configuration holding the Twilio Verify section.</param>
    /// <param name="sectionName">
    /// Name of the section to bind. Defaults to <see cref="TwilioVerifyOptions.SectionName"/>; pass the
    /// application's own when its settings already live under another name.
    /// </param>
    /// <param name="timeoutInSeconds">Timeout of each call to Twilio. Defaults to 30 seconds.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <remarks>
    /// This is the only place a caller names the provider: everything above it depends on
    /// <see cref="IPhoneVerifier"/>, so changing provider is changing this call.
    /// </remarks>
    public static IServiceCollection AddTwilioPhoneVerification(this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = TwilioVerifyOptions.SectionName,
        int timeoutInSeconds = DefaultTimeoutInSeconds)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentException.ThrowIfNullOrWhiteSpace(sectionName);

        services.Configure<TwilioVerifyOptions>(configuration.GetSection(sectionName));

        services.AddHttpClient<IPhoneVerifier, TwilioPhoneVerifier>(
            client => client.Timeout = TimeSpan.FromSeconds(timeoutInSeconds));

        return services;
    }
}
