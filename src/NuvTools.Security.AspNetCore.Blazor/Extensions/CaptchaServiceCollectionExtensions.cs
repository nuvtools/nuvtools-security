using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using NuvTools.Security.AspNetCore.Blazor.Captcha;
using NuvTools.Security.Captcha;

namespace NuvTools.Security.AspNetCore.Blazor.Extensions;

/// <summary>
/// Extension methods for registering the client-side CAPTCHA services.
/// </summary>
public static class CaptchaServiceCollectionExtensions
{
    /// <summary>
    /// Binds <see cref="CaptchaOptions"/> from the <see cref="CaptchaOptions.SectionName"/> section and
    /// adds the <see cref="ICaptchaService"/> to the service collection as a scoped service.
    /// </summary>
    /// <param name="services">The service collection to add the service to.</param>
    /// <param name="configuration">Configuration holding the CAPTCHA section.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <remarks>
    /// Only the client-side site keys are read here — the API key stays on the server.
    /// </remarks>
    public static IServiceCollection AddCaptcha(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.Configure<CaptchaOptions>(configuration.GetSection(CaptchaOptions.SectionName));

        return services.AddScoped<ICaptchaService, CaptchaService>();
    }
}
