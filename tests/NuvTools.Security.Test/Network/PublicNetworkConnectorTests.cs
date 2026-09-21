using NUnit.Framework;
using NuvTools.Security.Network;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NuvTools.Security.Test.Network;

/// <summary>
/// Drives a real <see cref="HttpClient"/> through the connect callback against a listener on loopback, so
/// what is asserted is where a socket actually went, not what a helper returned.
/// </summary>
[TestFixture]
public class PublicNetworkConnectorTests
{
    private static readonly NetworkAddressPolicy LoopbackAllowed =
        new(allowedNetworks: [IPNetwork.Parse("127.0.0.1/32")]);

    [Test]
    public void PublicOnly_ShouldRefuseALoopbackLiteral_BeforeConnecting()
    {
        using var client = new HttpClient(PublicNetworkConnector.CreateHandler());

        var exception = Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync("http://127.0.0.1:9/"));

        Assert.That(exception!.InnerException, Is.InstanceOf<NetworkAddressNotAllowedException>());
    }

    [Test]
    public void PublicOnly_ShouldRefuseTheInstanceMetadataEndpoint()
    {
        using var client = new HttpClient(PublicNetworkConnector.CreateHandler());

        var exception = Assert.ThrowsAsync<HttpRequestException>(
            () => client.GetAsync("http://169.254.169.254/metadata/instance"));

        Assert.That(exception!.InnerException, Is.InstanceOf<NetworkAddressNotAllowedException>());
    }

    [Test]
    public async Task AnAllowedAddress_ShouldBeReachedThroughTheCallback()
    {
        using var server = new OneShotHttpServer("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        using var client = new HttpClient(PublicNetworkConnector.CreateHandler(LoopbackAllowed));

        var body = await client.GetStringAsync($"http://127.0.0.1:{server.Port}/");

        Assert.That(body, Is.EqualTo("ok"));
    }

    [Test]
    public void ARedirectToADeniedAddress_ShouldBeRefusedAtTheSecondHop()
    {
        // The first hop is allowed; the Location it answers with is not. Following redirects is the
        // handler's default, and every hop opens a connection through the callback.
        using var server = new OneShotHttpServer(
            "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        using var client = new HttpClient(PublicNetworkConnector.CreateHandler(LoopbackAllowed));

        var exception = Assert.ThrowsAsync<HttpRequestException>(
            () => client.GetAsync($"http://127.0.0.1:{server.Port}/"));

        Assert.That(exception!.InnerException, Is.InstanceOf<NetworkAddressNotAllowedException>());
    }

    [Test]
    public void Apply_ShouldSwitchTheProxyOff()
    {
        using var handler = new SocketsHttpHandler { UseProxy = true, Proxy = new WebProxy("http://proxy.example.com:8080") };

        PublicNetworkConnector.Apply(handler);

        Assert.Multiple(() =>
        {
            Assert.That(handler.UseProxy, Is.False);
            Assert.That(handler.Proxy, Is.Null);
            Assert.That(handler.ConnectCallback, Is.Not.Null);
        });
    }

    /// <summary>Accepts one connection on loopback and answers it with a fixed response.</summary>
    private sealed class OneShotHttpServer : IDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);

        public int Port { get; }

        public OneShotHttpServer(string response)
        {
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;

            _ = Task.Run(async () =>
            {
                using var connection = await listener.AcceptTcpClientAsync();
                using var stream = connection.GetStream();

                var buffer = new byte[4096];
                _ = await stream.ReadAsync(buffer);

                await stream.WriteAsync(Encoding.ASCII.GetBytes(response));
            });
        }

        public void Dispose() => listener.Stop();
    }
}
