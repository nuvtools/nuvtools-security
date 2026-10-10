using Lacuna.RestPki.Api;
using NuvTools.Security.Certificate.Lacuna;
using NUnit.Framework;

namespace NuvTools.Security.Test.Certificate;

[TestFixture]
public class RestPkiOptionsTests
{
    [Test]
    public void Default_TrustsIcpBrasil()
    {
        Assert.That(new RestPkiOptions().GetSecurityContextId(), Is.EqualTo(StandardSecurityContexts.PkiBrazil));
    }

    [TestCase("")]
    [TestCase("  ")]
    [TestCase("PkiBrazil")]
    [TestCase("pkibrazil")]
    public void PkiBrazilOrBlank_TrustsIcpBrasil(string securityContext)
    {
        var options = new RestPkiOptions { SecurityContext = securityContext };

        Assert.That(options.GetSecurityContextId(), Is.EqualTo(StandardSecurityContexts.PkiBrazil));
    }

    [TestCase("LacunaTest")]
    [TestCase(" lacunatest ")]
    public void LacunaTest_TrustsTheTestRoots(string securityContext)
    {
        var options = new RestPkiOptions { SecurityContext = securityContext };

        Assert.That(options.GetSecurityContextId(), Is.EqualTo(StandardSecurityContexts.LacunaTest));
    }

    [Test]
    public void SecurityContextId_IsUsedAsIs()
    {
        var id = Guid.NewGuid();
        var options = new RestPkiOptions { SecurityContext = id.ToString() };

        Assert.That(options.GetSecurityContextId(), Is.EqualTo(id));
    }

    [Test]
    public void UnknownName_IsRefusedInsteadOfFallingBack()
    {
        var options = new RestPkiOptions { SecurityContext = "LacunaTests" };

        Assert.That(options.GetSecurityContextId, Throws.InvalidOperationException);
    }
}
