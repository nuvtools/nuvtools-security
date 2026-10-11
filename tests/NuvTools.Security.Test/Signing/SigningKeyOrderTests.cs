using NuvTools.Security.Signing.Azure;
using NUnit.Framework;

namespace NuvTools.Security.Test.Signing;

[TestFixture]
public class SigningKeyOrderTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 10, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Delay = TimeSpan.FromHours(1);

    [Test]
    public void NewestVersionPastTheDelay_Signs_AndTheRestFollowNewestFirst()
    {
        var arranged = SigningKeyOrder.Arrange(
            [Version("old", days: 60), Version("current", days: 30), Version("older", days: 90)], Now, Delay);

        Assert.That(arranged.Select(version => version.Version), Is.EqualTo(new[] { "current", "old", "older" }));
    }

    [Test]
    public void VersionCreatedWithinTheDelay_IsPublishedButDoesNotSignYet()
    {
        var arranged = SigningKeyOrder.Arrange(
            [Version("current", days: 30), new SigningKeyVersion("rotated", Now.AddMinutes(-10))], Now, Delay);

        Assert.That(arranged.Select(version => version.Version), Is.EqualTo(new[] { "current", "rotated" }));
    }

    [Test]
    public void VersionExactlyAtTheDelay_Signs()
    {
        var arranged = SigningKeyOrder.Arrange(
            [Version("current", days: 30), new SigningKeyVersion("rotated", Now - Delay)], Now, Delay);

        Assert.That(arranged[0].Version, Is.EqualTo("rotated"));
    }

    [Test]
    public void WhenNoVersionIsPastTheDelay_TheOldestSigns()
    {
        var arranged = SigningKeyOrder.Arrange(
            [new SigningKeyVersion("second", Now.AddMinutes(-5)), new SigningKeyVersion("first", Now.AddMinutes(-20))], Now, Delay);

        Assert.That(arranged.Select(version => version.Version), Is.EqualTo(new[] { "first", "second" }));
    }

    [Test]
    public void NoVersions_ArrangeToNothing()
        => Assert.That(SigningKeyOrder.Arrange([], Now, Delay), Is.Empty);

    private static SigningKeyVersion Version(string name, int days) => new(name, Now.AddDays(-days));
}
