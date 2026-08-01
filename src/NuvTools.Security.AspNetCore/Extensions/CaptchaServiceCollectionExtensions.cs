using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using NuvTools.Security.AspNetCore.Captcha;
using NuvTools.Security.Captcha;

namespace NuvTools.Security.AspNetCore.Extensions;

/// <summary>
/// Extension methods for registering the CAPTCHA verification services.
/// </summary>
public static class CaptchaServiceCollectionExtensions
{
    private const int DefaultTimeoutInSeconds = 10;

    /// <summary>
    /// Binds <see cref="CaptchaOptions"/> from the <see cref="CaptchaOptions.SectionName"/> section and
    /// registers <see cref="ICaptchaVerifier"/> with its own <see cref="HttpClient"/>.
    /// </summary>
    /// <param name="services">The service collection to add the services to.</param>
    /// <param name="configuration">Configuration holding the CAPTCHA section.</param>
    /// <param name="timeoutInSeconds">Timeout of the assessment call. Defaults to 10 seconds.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <remarks>
    /// The <see cref="ValidateCaptchaAttribute"/> is applied per endpoint — this method only wires up
    /// the services it depends on.
    /// </remarks>
    public static IServiceCollection AddCaptcha(this IServiceCollection services,
        IConfiguration configuration,
        int timeoutInSeconds = DefaultTimeoutInSeconds)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.Configure<CaptchaOptions>(configuration.GetSection(CaptchaOptions.SectionName));

        services.AddHttpClient<ICaptchaVerifier, ReCaptchaEnterpriseVerifier>(
            client => client.Timeout = TimeSpan.FromSeconds(timeoutInSeconds));

        return services;
    }
}
