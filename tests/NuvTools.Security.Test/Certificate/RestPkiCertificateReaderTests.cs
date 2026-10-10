using Lacuna.RestPki.Api;
using NuvTools.Security.Certificate.Lacuna;
using NUnit.Framework;

namespace NuvTools.Security.Test.Certificate;

[TestFixture]
public class RestPkiCertificateReaderTests
{
    private static CertificateModel CompanyCertificate() => new()
    {
        SubjectName = new NameModel { CommonName = "ACME LTDA:11222333000181", EmailAddress = "contato@acme.test" },
        IssuerDisplayName = "AC Test v5",
        ValidityEnd = new DateTimeOffset(2027, 3, 1, 12, 0, 0, TimeSpan.Zero),
        BinaryThumbprintSHA256 = [0xAB, 0xCD, 0x01],
        PkiBrazil = new PkiBrazilCertificateModel
        {
            Cpf = "529.982.247-25",
            Cnpj = "11.222.333/0001-81",
            Responsavel = "Maria Silva",
            CompanyName = "ACME LTDA"
        }
    };

    [Test]
    public void CompanyCertificate_IsReadWithDigitsOnlyDocuments()
    {
        var details = RestPkiCertificateReader.ToDetails(CompanyCertificate());

        Assert.Multiple(() =>
        {
            Assert.That(details.Subject.Name, Is.EqualTo("ACME LTDA:11222333000181"));
            Assert.That(details.Subject.Email, Is.EqualTo("contato@acme.test"));
            Assert.That(details.Subject.Cpf, Is.EqualTo("52998224725"));
            Assert.That(details.Subject.Cnpj, Is.EqualTo("11222333000181"));
            Assert.That(details.Subject.CompanyName, Is.EqualTo("ACME LTDA"));
            Assert.That(details.ResponsibleName, Is.EqualTo("Maria Silva"));
            Assert.That(details.IssuerName, Is.EqualTo("AC Test v5"));
            Assert.That(details.ValidUntil, Is.EqualTo(new DateTimeOffset(2027, 3, 1, 12, 0, 0, TimeSpan.Zero)));
            Assert.That(details.ThumbprintSha256, Is.EqualTo("ABCD01"));
        });
    }

    [Test]
    public void CertificateOutsideIcpBrasil_HasNoDocuments()
    {
        var certificate = new CertificateModel { SubjectName = new NameModel { CommonName = "John Doe" } };

        var details = RestPkiCertificateReader.ToDetails(certificate);

        Assert.Multiple(() =>
        {
            Assert.That(details.Subject.Name, Is.EqualTo("John Doe"));
            Assert.That(details.Subject.Cpf, Is.Null);
            Assert.That(details.Subject.Cnpj, Is.Null);
            Assert.That(details.ResponsibleName, Is.Null);
            Assert.That(details.ThumbprintSha256, Is.Null);
        });
    }

    [Test]
    public void BlankValues_AreReportedAsMissing()
    {
        var certificate = CompanyCertificate();
        certificate.PkiBrazil.Cnpj = " ";
        certificate.PkiBrazil.CompanyName = "";
        certificate.SubjectName.EmailAddress = "";

        var details = RestPkiCertificateReader.ToDetails(certificate);

        Assert.Multiple(() =>
        {
            Assert.That(details.Subject.Cnpj, Is.Null);
            Assert.That(details.Subject.CompanyName, Is.Null);
            Assert.That(details.Subject.Email, Is.Null);
        });
    }
}
