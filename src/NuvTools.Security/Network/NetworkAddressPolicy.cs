using System.Net;
using System.Net.Sockets;

namespace NuvTools.Security.Network;

/// <summary>
/// Decides whether an outbound connection may reach an address: the building block against
/// server-side request forgery (SSRF) when an application fetches a URL somebody else supplied.
/// </summary>
/// <remarks>
/// <para>
/// The decision is taken on the <b>IP address</b>, never on the text of the URL. A host name proves
/// nothing about where it resolves — a public domain can carry an <c>A</c> record of <c>10.0.0.5</c>, and
/// can change it between a check and the connection (DNS rebinding). Pair this policy with
/// <see cref="PublicNetworkConnector"/>, which applies it to the address a socket actually connects to.
/// </para>
/// <para>
/// By default only publicly routable unicast addresses are allowed. Denied: loopback, private (RFC 1918
/// and IPv6 unique-local), link-local (which includes the cloud instance metadata endpoint
/// <c>169.254.169.254</c>), carrier-grade NAT, documentation and benchmarking ranges, multicast,
/// reserved space, the IPv6 transition prefixes that embed an IPv4 address, and Azure's platform
/// address <c>168.63.129.16</c>, which is public in form and internal in fact.
/// </para>
/// </remarks>
public sealed class NetworkAddressPolicy
{
    private static readonly IPNetwork[] DefaultDeniedNetworks =
    [
        // IPv4
        IPNetwork.Parse("0.0.0.0/8"),          // "this network"
        IPNetwork.Parse("10.0.0.0/8"),         // private
        IPNetwork.Parse("100.64.0.0/10"),      // carrier-grade NAT
        IPNetwork.Parse("127.0.0.0/8"),        // loopback
        IPNetwork.Parse("168.63.129.16/32"),   // Azure platform (WireServer, DNS, health probes)
        IPNetwork.Parse("169.254.0.0/16"),     // link-local, instance metadata
        IPNetwork.Parse("172.16.0.0/12"),      // private
        IPNetwork.Parse("192.0.0.0/24"),       // IETF protocol assignments
        IPNetwork.Parse("192.0.2.0/24"),       // documentation
        IPNetwork.Parse("192.88.99.0/24"),     // 6to4 relay anycast
        IPNetwork.Parse("192.168.0.0/16"),     // private
        IPNetwork.Parse("198.18.0.0/15"),      // benchmarking
        IPNetwork.Parse("198.51.100.0/24"),    // documentation
        IPNetwork.Parse("203.0.113.0/24"),     // documentation
        IPNetwork.Parse("224.0.0.0/4"),        // multicast
        IPNetwork.Parse("240.0.0.0/4"),        // reserved, and the limited broadcast address

        // IPv6
        IPNetwork.Parse("::/96"),              // unspecified, loopback, deprecated IPv4-compatible
        IPNetwork.Parse("64:ff9b::/96"),       // NAT64, embeds an IPv4 address
        IPNetwork.Parse("64:ff9b:1::/48"),     // local-use NAT64
        IPNetwork.Parse("100::/64"),           // discard
        IPNetwork.Parse("2001::/23"),          // IETF protocol assignments, Teredo included
        IPNetwork.Parse("2001:db8::/32"),      // documentation
        IPNetwork.Parse("2002::/16"),          // 6to4, embeds an IPv4 address
        IPNetwork.Parse("fc00::/7"),           // unique-local
        IPNetwork.Parse("fe80::/10"),          // link-local
        IPNetwork.Parse("ff00::/8")            // multicast
    ];

    /// <summary>
    /// Host names refused before any lookup. A second line only: a name that is not listed here is still
    /// judged by the address it resolves to.
    /// </summary>
    private static readonly string[] DefaultDeniedHostSuffixes = [".internal", ".local", ".localhost"];

    private readonly IPNetwork[] deniedNetworks;
    private readonly IPNetwork[] allowedNetworks;
    private readonly string[] deniedHostSuffixes;

    /// <summary>A policy allowing publicly routable addresses only.</summary>
    public static NetworkAddressPolicy PublicOnly { get; } = new();

    /// <summary>Creates a policy.</summary>
    /// <param name="allowedNetworks">
    /// Networks allowed even though the defaults deny them — an internal backend a deployment trusts.
    /// Checked before the denied list, so keep it as narrow as the need.
    /// </param>
    /// <param name="additionalDeniedNetworks">Networks denied on top of the defaults.</param>
    /// <param name="additionalDeniedHostSuffixes">Host name suffixes denied on top of the defaults.</param>
    public NetworkAddressPolicy(
        IEnumerable<IPNetwork>? allowedNetworks = null,
        IEnumerable<IPNetwork>? additionalDeniedNetworks = null,
        IEnumerable<string>? additionalDeniedHostSuffixes = null)
    {
        this.allowedNetworks = [.. allowedNetworks ?? []];
        deniedNetworks = [.. DefaultDeniedNetworks, .. additionalDeniedNetworks ?? []];
        deniedHostSuffixes = [.. DefaultDeniedHostSuffixes, .. (additionalDeniedHostSuffixes ?? []).Select(NormalizeSuffix)];
    }

    /// <summary>Whether a connection to this address is allowed.</summary>
    /// <remarks>
    /// An IPv4-mapped IPv6 address (<c>::ffff:127.0.0.1</c>) is judged as the IPv4 address it carries,
    /// which is where the socket ends up.
    /// </remarks>
    public bool IsAllowed(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();

        if (address.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)) return false;

        if (Array.Exists(allowedNetworks, network => network.Contains(address))) return true;

        return !Array.Exists(deniedNetworks, network => network.Contains(address));
    }

    /// <summary>
    /// Whether a host name may be looked up at all. Names that can only mean "inside" — <c>localhost</c>
    /// and the internal suffixes — are refused without asking DNS.
    /// </summary>
    public bool IsHostAllowed(string host)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);

        var normalized = host.Trim().TrimEnd('.').ToLowerInvariant();

        if (normalized == "localhost") return false;

        return !Array.Exists(deniedHostSuffixes, suffix => normalized.EndsWith(suffix, StringComparison.Ordinal));
    }

    /// <summary>
    /// Resolves a host and returns its addresses, throwing when the name or any address it resolves to is
    /// not allowed.
    /// </summary>
    /// <remarks>
    /// <b>Any</b> denied address refuses the whole name, not just that address. A name answering with one
    /// public and one private address is either misconfigured or an attempt to win a race, and neither is
    /// worth connecting to.
    /// </remarks>
    /// <exception cref="NetworkAddressNotAllowedException">The host or one of its addresses is denied.</exception>
    public async Task<IPAddress[]> ResolveAllowedAsync(string host, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);

        var trimmed = host.Trim().Trim('[', ']');

        if (IPAddress.TryParse(trimmed, out var literal))
            return IsAllowed(literal) ? [literal] : throw new NetworkAddressNotAllowedException(host, literal);

        if (!IsHostAllowed(trimmed)) throw new NetworkAddressNotAllowedException(host, null);

        var addresses = await Dns.GetHostAddressesAsync(trimmed, cancellationToken).ConfigureAwait(false);

        if (addresses.Length == 0) throw new NetworkAddressNotAllowedException(host, null);

        foreach (var address in addresses)
            if (!IsAllowed(address)) throw new NetworkAddressNotAllowedException(host, address);

        return addresses;
    }

    private static string NormalizeSuffix(string suffix)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(suffix);

        var normalized = suffix.Trim().ToLowerInvariant();

        return normalized.StartsWith('.') ? normalized : "." + normalized;
    }
}
