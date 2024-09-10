using Microsoft.AspNetCore.Http;

namespace NuvTools.Security.AspNetCore.Services;

public class CurrentUserService(IHttpContextAccessor httpContextAccessor)
{
    public string? NameIdentifier { get; } = httpContextAccessor.HttpContext?.User?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
    public string? RemoteIpAddress { get; } = httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString();
    public int? RemotePort { get; } = httpContextAccessor.HttpContext?.Connection.RemotePort;
    public string FullRemoteAddress { get { return RemoteIpAddress + ":" + RemotePort; } }
    public List<KeyValuePair<string, string>>? Claims { get; } = httpContextAccessor.HttpContext?.User?.Claims.AsEnumerable().Select(item => new KeyValuePair<string, string>(item.Type, item.Value)).ToList();
}