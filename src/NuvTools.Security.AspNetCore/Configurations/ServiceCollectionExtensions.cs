using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace NuvTools.Security.AspNetCore.Configurations;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Configures security section (SecurityConfigurationSection) to use with TOptions injection.
    /// </summary>
    /// <param name="services"></param>
    /// <param name="configuration"></param>
    /// <param name="sectionName">Just in case to use another section instead the default one.</param>
    /// <returns></returns>
    public static IServiceCollection AddSecurityConfiguration(
                   this IServiceCollection services,
                   IConfiguration configuration, string sectionName = "NuvTools.Security")
    {
        services.Configure<SecurityConfigurationSection>(configuration.GetSection(sectionName));
        return services;
    }
}