using System.Net;

namespace NuvTools.Security.Network;

/// <summary>
/// Thrown when an outbound connection would reach a host or an address that
/// <see cref="NetworkAddressPolicy"/> denies.
/// </summary>
/// <remarks>
/// Raised from a <see cref="System.Net.Http.SocketsHttpHandler.ConnectCallback"/>, it reaches the caller of
/// <see cref="HttpClient"/> as the inner exception of an <see cref="HttpRequestException"/>. The message
/// names the host but not the address, so it is safe to log and still says which URL was refused; the
/// address is on <see cref="Address"/> for whoever needs it.
/// </remarks>
public sealed class NetworkAddressNotAllowedException : IOException
{
    /// <summary>The host that was asked for, as it appeared in the request.</summary>
    public string Host { get; }

    /// <summary>The denied address, or <see langword="null"/> when the host name itself was refused.</summary>
    public IPAddress? Address { get; }

    /// <summary>Creates the exception.</summary>
    public NetworkAddressNotAllowedException(string host, IPAddress? address)
        : base($"Connections to '{host}' are not allowed: it resolves to a network this application may not reach.")
    {
        Host = host;
        Address = address;
    }
}
