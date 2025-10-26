using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace NuvTools.Security.AspNetCore.Services;

/// <summary>
/// Provides information about the currently authenticated user and their connection details
/// within an ASP.NET Core application.
/// </summary>
/// <remarks>
/// This service is useful for retrieving user identity data (claims, identifiers, IP address, etc.)
/// in controllers, Razor pages, or application services where dependency injection is available.
/// </remarks>
public class CurrentUserService(IHttpContextAccessor httpContextAccessor)
{
    private readonly HttpContext? _httpContext = httpContextAccessor.HttpContext;

    /// <summary>
    /// Gets the unique identifier (NameIdentifier claim) of the current authenticated user.
    /// </summary>
    /// <remarks>
    /// This typically corresponds to the <c>sub</c> claim in JWT-based authentication or the user ID in ASP.NET Identity.
    /// </remarks>
    public string? NameIdentifier =>
        _httpContext?.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

    /// <summary>
    /// Gets the remote IP address of the current HTTP request, if available.
    /// </summary>
    public string? RemoteIpAddress =>
        _httpContext?.Connection?.RemoteIpAddress?.ToString();

    /// <summary>
    /// Gets the remote port of the current HTTP request, if available.
    /// </summary>
    public int? RemotePort =>
        _httpContext?.Connection?.RemotePort;

    /// <summary>
    /// Gets a string combining the remote IP address and port number.
    /// </summary>
    /// <remarks>
    /// If the remote address is unavailable, this property returns an empty string.
    /// </remarks>
    public string FullRemoteAddress =>
        string.IsNullOrWhiteSpace(RemoteIpAddress)
            ? string.Empty
            : $"{RemoteIpAddress}:{RemotePort}";

    /// <summary>
    /// Gets all claims of the current authenticated user as a collection of key/value pairs.
    /// </summary>
    /// <remarks>
    /// Each item represents a claim type and its corresponding value.
    /// </remarks>
    public IReadOnlyList<KeyValuePair<string, string>> Claims =>
        _httpContext?.User?.Claims?
            .Select(c => new KeyValuePair<string, string>(c.Type, c.Value))
            .ToList()
        ?? [];
}
