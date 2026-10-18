using System.Globalization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;

namespace NuvTools.Security.AspNetCore.RateLimiting;

/// <summary>
/// Extension methods for limiting anonymous endpoints, such as sign-in, sign-up and password
/// recovery, by the address a request comes from.
/// </summary>
public static class RateLimiterOptionsExtensions
{
    /// <summary>
    /// Adds a policy that lets each client address make <paramref name="permitLimit"/> requests per
    /// <paramref name="window"/>, and rejects the rest at once.
    /// </summary>
    /// <param name="options">The rate limiter options to add the policy to.</param>
    /// <param name="policyName">The name an endpoint uses to apply the policy.</param>
    /// <param name="permitLimit">Requests allowed per address in each window.</param>
    /// <param name="window">Length of the window.</param>
    /// <returns>The options for chaining.</returns>
    /// <remarks>
    /// <para>
    /// The partition key is the policy name followed by the address. Each policy therefore counts on
    /// its own: using up the allowance for asking for a reset link does not use up the allowance for
    /// spending one.
    /// </para>
    /// <para>
    /// There is no queue. A caller past the limit gets the rejection straight away instead of having
    /// its connection held open.
    /// </para>
    /// <para>
    /// The address is <see cref="ConnectionInfo.RemoteIpAddress"/>. Behind a proxy, call
    /// <c>UseForwardedHeaders</c> before <c>UseRateLimiter</c>, or every caller shares the proxy's
    /// address. A request with no address falls into one shared bucket rather than going unlimited.
    /// An address is something a caller can vary, so this bounds noise and unsophisticated scripts;
    /// it does not replace account lockout or a uniform answer that hides whether an account exists.
    /// </para>
    /// </remarks>
    public static RateLimiterOptions AddFixedWindowPerClientAddress(this RateLimiterOptions options,
        string policyName,
        int permitLimit,
        TimeSpan window)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(policyName);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(permitLimit);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(window, TimeSpan.Zero);

        options.AddPolicy(policyName, context =>
            RateLimitPartition.GetFixedWindowLimiter(
                $"{policyName}|{context.Connection.RemoteIpAddress?.ToString() ?? "unknown"}",
                _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = permitLimit,
                    Window = window,
                    QueueLimit = 0,
                    AutoReplenishment = true
                }));

        return options;
    }

    /// <summary>
    /// Sets the response status to 429 and, when the limiter knows it, the <c>Retry-After</c> header
    /// in seconds.
    /// </summary>
    /// <param name="context">The context passed to <see cref="RateLimiterOptions.OnRejected"/>.</param>
    /// <remarks>
    /// Writes no body, so an API can add its own error envelope and a page can render its own message.
    /// </remarks>
    public static void SetTooManyRequests(this OnRejectedContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;

        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
            context.HttpContext.Response.Headers.RetryAfter =
                ((int)Math.Ceiling(retryAfter.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
    }
}
