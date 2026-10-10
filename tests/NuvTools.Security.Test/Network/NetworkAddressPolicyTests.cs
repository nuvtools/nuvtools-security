using NUnit.Framework;
using NuvTools.Security.Network;
using System.Net;

namespace NuvTools.Security.Test.Network;

[TestFixture]
public class NetworkAddressPolicyTests
{
    [TestCase("127.0.0.1")]
    [TestCase("10.1.2.3")]
    [TestCase("172.16.0.1")]
    [TestCase("172.31.255.255")]
    [TestCase("192.168.1.10")]
    [TestCase("169.254.169.254")]
    [TestCase("168.63.129.16")]
    [TestCase("100.64.0.1")]
    [TestCase("0.0.0.0")]
    [TestCase("192.0.2.1")]
    [TestCase("198.18.0.1")]
    [TestCase("224.0.0.1")]
    [TestCase("255.255.255.255")]
    [TestCase("::1")]
    [TestCase("::")]
    [TestCase("fd00::1")]
    [TestCase("fe80::1")]
    [TestCase("ff02::1")]
    [TestCase("2001:db8::1")]
    [TestCase("64:ff9b::a00:1")]
    [TestCase("2002:a00:1::")]
    public void PublicOnly_ShouldDeny_NonPublicAddresses(string address)
    {
        Assert.That(NetworkAddressPolicy.PublicOnly.IsAllowed(IPAddress.Parse(address)), Is.False);
    }

    [TestCase("8.8.8.8")]
    [TestCase("20.85.92.240")]
    [TestCase("172.32.0.1")]
    [TestCase("2606:4700:4700::1111")]
    public void PublicOnly_ShouldAllow_PublicAddresses(string address)
    {
        Assert.That(NetworkAddressPolicy.PublicOnly.IsAllowed(IPAddress.Parse(address)), Is.True);
    }

    [Test]
    public void IsAllowed_ShouldJudgeAnIPv4MappedAddress_AsTheIPv4AddressItCarries()
    {
        // ::ffff:127.0.0.1 is outside every IPv6 range and lands on loopback all the same.
        Assert.That(NetworkAddressPolicy.PublicOnly.IsAllowed(IPAddress.Parse("::ffff:127.0.0.1")), Is.False);
        Assert.That(NetworkAddressPolicy.PublicOnly.IsAllowed(IPAddress.Parse("::ffff:8.8.8.8")), Is.True);
    }

    [Test]
    public void AllowedNetworks_ShouldOverrideTheDefaults_OnlyWhereListed()
    {
        var policy = new NetworkAddressPolicy(allowedNetworks: [IPNetwork.Parse("10.20.0.0/16")]);

        Assert.That(policy.IsAllowed(IPAddress.Parse("10.20.5.5")), Is.True);
        Assert.That(policy.IsAllowed(IPAddress.Parse("10.21.5.5")), Is.False);
        Assert.That(policy.IsAllowed(IPAddress.Parse("169.254.169.254")), Is.False);
    }

    [Test]
    public void AdditionalDeniedNetworks_ShouldDenyAddressesThatArePublicInForm()
    {
        var policy = new NetworkAddressPolicy(additionalDeniedNetworks: [IPNetwork.Parse("20.85.92.0/24")]);

        Assert.That(policy.IsAllowed(IPAddress.Parse("20.85.92.240")), Is.False);
    }

    [TestCase("localhost")]
    [TestCase("LOCALHOST.")]
    [TestCase("api.internal")]
    [TestCase("printer.local")]
    [TestCase("app.localhost")]
    public void IsHostAllowed_ShouldRefuseNamesThatCanOnlyMeanInside(string host)
    {
        Assert.That(NetworkAddressPolicy.PublicOnly.IsHostAllowed(host), Is.False);
    }

    [Test]
    public void IsHostAllowed_ShouldAcceptAnOrdinaryName_AndAdditionalSuffixesShouldRefuse()
    {
        var policy = new NetworkAddressPolicy(additionalDeniedHostSuffixes: ["azurecontainerapps.io"]);

        Assert.That(NetworkAddressPolicy.PublicOnly.IsHostAllowed("api.example.com"), Is.True);
        Assert.That(policy.IsHostAllowed("geo.redbay.eastus2.azurecontainerapps.io"), Is.False);
    }

    [Test]
    public async Task ResolveAllowedAsync_ShouldRefuseADeniedLiteral_WithoutAskingDns()
    {
        var exception = await Assert.ThrowsAsync<NetworkAddressNotAllowedException>(
            () => NetworkAddressPolicy.PublicOnly.ResolveAllowedAsync("[::1]"));

        Assert.That(exception!.Address, Is.EqualTo(IPAddress.IPv6Loopback));
    }

    [Test]
    public async Task ResolveAllowedAsync_ShouldRefuseLocalhostByName()
    {
        var exception = await Assert.ThrowsAsync<NetworkAddressNotAllowedException>(
            () => NetworkAddressPolicy.PublicOnly.ResolveAllowedAsync("localhost"));

        Assert.That(exception!.Address, Is.Null);
    }
}
