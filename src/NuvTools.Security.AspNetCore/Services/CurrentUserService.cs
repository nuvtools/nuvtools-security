using Microsoft.AspNetCore.Http;

namespace NuvTools.Security.AspNetCore.Services;

public class CurrentUserService
{
    public CurrentUserService(IHttpContextAccessor httpContextAccessor)
    {
        NameIdentifier = httpContextAccessor.HttpContext?.User?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        Claims = httpContextAccessor.HttpContext?.User?.Claims.AsEnumerable().Select(item => new KeyValuePair<string, string>(item.Type, item.Value)).ToList();
        RemoteIpAddress = httpContextAccessor.HttpContext.Connection.RemoteIpAddress?.ToString();
        RemotePort = httpContextAccessor.HttpContext.Connection.RemotePort;
    }

    public string NameIdentifier { get; }
    public string RemoteIpAddress { get; }
    public int RemotePort { get; }
    public string FullRemoteAddress { get { return RemoteIpAddress + ":" + RemotePort; } }
    public List<KeyValuePair<string, string>> Claims { get; }
}