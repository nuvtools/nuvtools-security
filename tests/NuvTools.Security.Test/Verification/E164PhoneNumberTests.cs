using NuvTools.Security.Verification;
using NUnit.Framework;

namespace NuvTools.Security.Test.Verification;

[TestFixture]
public class E164PhoneNumberTests
{
    [TestCase("(11) 98765-4321", "+5511987654321")]
    [TestCase("011 98765 4321", "+5511987654321")]
    [TestCase("+55 11 98765-4321", "+5511987654321")]
    [TestCase("0055 11 98765-4321", "+5511987654321")]
    [TestCase("+1 (415) 555-0100", "+14155550100")]
    public void TryNormalize_TurnsWhatPeopleTypeIntoE164(string input, string expected)
    {
        Assert.That(E164PhoneNumber.TryNormalize(input, "55", out var number), Is.True);
        Assert.That(number, Is.EqualTo(expected));
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("abc")]
    [TestCase("11 9876x4321")]
    [TestCase("+0 11 98765 4321")]
    [TestCase("+55 11 98765 4321 1234 5678")]
    [TestCase("123")]
    public void TryNormalize_RefusesWhatIsNotAPhoneNumber(string? input)
    {
        Assert.That(E164PhoneNumber.TryNormalize(input, "55", out var number), Is.False);
        Assert.That(number, Is.Empty);
    }

    [TestCase("+5511987654321", true)]
    [TestCase("5511987654321", false)]
    [TestCase("+55 11 987654321", false)]
    [TestCase("+0511987654321", false)]
    public void IsValid_AcceptsOnlyE164(string value, bool expected)
        => Assert.That(E164PhoneNumber.IsValid(value), Is.EqualTo(expected));
}
