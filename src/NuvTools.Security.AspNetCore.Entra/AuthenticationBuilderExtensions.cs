using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace NuvTools.Security.AspNetCore.Entra;

/// <summary>Registers the Entra workload scheme.</summary>
public static class AuthenticationBuilderExtensions
{
    /// <summary>
    /// Adds a bearer scheme that admits an Entra token issued for <see cref="EntraWorkloadOptions.Audience"/>
    /// to one of <see cref="EntraWorkloadOptions.AllowedApplicationIds"/>, and nothing else.
    /// </summary>
    /// <remarks>
    /// <para>
    /// For service-to-service calls with no secret: the caller is a managed identity, which asks Entra
    /// for a token per call (<c>DefaultAzureCredential</c>), and nothing on either side holds a
    /// credential to rotate or leak.
    /// </para>
    /// <para>
    /// Both issuer forms are accepted, because a managed identity is normally issued a v1 token
    /// (<c>sts.windows.net</c>) while the signing keys are read from the v2 metadata; the keys are the
    /// same set. Claims keep their token names (<see cref="EntraWorkloadClaims"/>).
    /// </para>
    /// <para>
    /// Unconfigured means <b>refuse</b>: the scheme then has no signing keys and admits nobody. It is
    /// never the default scheme by accident — name it on the endpoints it guards.
    /// </para>
    /// </remarks>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="scheme">The scheme's name, which the guarded endpoints name.</param>
    /// <param name="configure">Fills in the tenant, the audience and the allowed applications.</param>
    public static AuthenticationBuilder AddEntraWorkload(
        this AuthenticationBuilder builder, string scheme, Action<EntraWorkloadOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(scheme);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new EntraWorkloadOptions();
        configure(options);

        return builder.AddJwtBearer(scheme, bearer => Configure(bearer, options));
    }

    private static void Configure(JwtBearerOptions bearer, EntraWorkloadOptions options)
    {
        bearer.MapInboundClaims = false;

        if (!options.IsConfigured)
        {
            // No metadata address, so nothing is fetched and nothing can be resolved later: an empty
            // configuration is a permanent absence of signing keys.
            bearer.Configuration = new OpenIdConnectConfiguration();
            bearer.TokenValidationParameters = new TokenValidationParameters { ValidateIssuerSigningKey = true };
            return;
        }

        bearer.Authority = $"https://login.microsoftonline.com/{options.TenantId}/v2.0";

        bearer.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuers =
            [
                $"https://login.microsoftonline.com/{options.TenantId}/v2.0",
                $"https://sts.windows.net/{options.TenantId}/"
            ],
            ValidateAudience = true,
            ValidAudience = options.Audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(1)
        };

        var allowed = options.AllowedApplicationIds
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        bearer.Events = new JwtBearerEvents
        {
            OnTokenValidated = context =>
            {
                // Neither claim is optional on an application token, so a token with neither is a
                // shape this scheme does not admit.
                var applicationId = context.Principal?.GetEntraWorkloadApplicationId();

                if (applicationId is null || !allowed.Contains(applicationId))
                    context.Fail("The calling application is not allowed.");

                return Task.CompletedTask;
            }
        };
    }
}
