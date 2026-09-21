using System.Net;
using System.Net.Http;
using System.Net.Sockets;

namespace NuvTools.Security.Network;

/// <summary>
/// Makes a <see cref="SocketsHttpHandler"/> connect only to addresses a <see cref="NetworkAddressPolicy"/>
/// allows, judged at the moment of connecting.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why at the socket and not before the request.</b> Checking a URL, resolving it and then letting
/// <see cref="HttpClient"/> resolve it again leaves a gap an attacker controls: their DNS answers a public
/// address to the check and a private one to the connection. Here the address that is checked is the
/// address the socket connects to — there is no second lookup.
/// </para>
/// <para>
/// Every connection goes through the callback, redirects included, so a public URL answering
/// <c>302 Location: http://169.254.169.254/</c> is refused at the second hop. The proxy is switched off,
/// because through a proxy the callback would only ever see the proxy's address.
/// </para>
/// <para>
/// Works with anything built on <see cref="SocketsHttpHandler"/>: an <see cref="HttpClient"/>, an
/// <c>IHttpClientFactory</c> primary handler, or a reverse proxy's forwarder handler.
/// </para>
/// </remarks>
public static class PublicNetworkConnector
{
    /// <summary>Creates a handler that connects only where <paramref name="policy"/> allows.</summary>
    /// <param name="policy">The policy; <see cref="NetworkAddressPolicy.PublicOnly"/> when omitted.</param>
    public static SocketsHttpHandler CreateHandler(NetworkAddressPolicy? policy = null)
    {
        var handler = new SocketsHttpHandler();

        Apply(handler, policy);

        return handler;
    }

    /// <summary>Applies the policy to an existing handler, replacing its connect callback and its proxy.</summary>
    /// <param name="handler">The handler to restrict.</param>
    /// <param name="policy">The policy; <see cref="NetworkAddressPolicy.PublicOnly"/> when omitted.</param>
    public static void Apply(SocketsHttpHandler handler, NetworkAddressPolicy? policy = null)
    {
        ArgumentNullException.ThrowIfNull(handler);

        handler.UseProxy = false;
        handler.Proxy = null;
        handler.ConnectCallback = CreateConnectCallback(policy ?? NetworkAddressPolicy.PublicOnly);
    }

    /// <summary>The connect callback itself, for a handler configured elsewhere.</summary>
    public static Func<SocketsHttpConnectionContext, CancellationToken, ValueTask<Stream>> CreateConnectCallback(
        NetworkAddressPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        return async (context, cancellationToken) =>
        {
            var endPoint = context.DnsEndPoint;

            var addresses = await policy.ResolveAllowedAsync(endPoint.Host, cancellationToken).ConfigureAwait(false);

            SocketException? lastFailure = null;

            foreach (var address in addresses)
            {
                var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };

                try
                {
                    await socket.ConnectAsync(new IPEndPoint(address, endPoint.Port), cancellationToken).ConfigureAwait(false);

                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch (SocketException ex)
                {
                    socket.Dispose();
                    lastFailure = ex;
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            }

            throw lastFailure ?? new SocketException((int)SocketError.HostNotFound);
        };
    }
}
