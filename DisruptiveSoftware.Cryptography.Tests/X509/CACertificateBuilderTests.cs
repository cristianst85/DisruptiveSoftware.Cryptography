using DisruptiveSoftware.Cryptography.BouncyCastle.Extensions;
using DisruptiveSoftware.Cryptography.Tests.Extensions;
using NUnit.Framework;
using Org.BouncyCastle.Math;
using System;

namespace DisruptiveSoftware.Cryptography.X509.Tests
{
    [TestFixture]
    public class CACertificateBuilderTests
    {
        [Test]
        public void GenerateCertificate()
        {
            var now = DateTime.UtcNow;

            var caCertificateBuilderResult = new CACertificateBuilder()
                .SetSerialNumber(1)
                .SetKeySize(2048)
                .SetSubjectDN("Test CA", "Organization Unit", "Organization", "Locality", "Country")
                .SetNotBefore(now)
                .SetNotAfter(now.AddMonths(24))
                .Build();

            Assert.That(() => caCertificateBuilderResult, Is.Not.Null);
            Assert.That(() => caCertificateBuilderResult.Certificate, Is.Not.Null);

            Assert.That(() => caCertificateBuilderResult.Certificate.SerialNumber, Is.EqualTo(BigInteger.One));

            Assert.That(() => caCertificateBuilderResult.Certificate.SigAlgName, Is.EqualTo("SHA-256withRSA"));

            Assert.That(() => caCertificateBuilderResult.Certificate.NotBefore, Is.EqualTo(now.TruncateMilliseconds()));
            Assert.That(() => caCertificateBuilderResult.Certificate.NotAfter, Is.EqualTo(now.AddMonths(24).TruncateMilliseconds()));

            Assert.That(() => caCertificateBuilderResult.Certificate.IsSelfSigned(), Is.True);

            Assert.That(() => caCertificateBuilderResult.Certificate.SubjectDN.ToString(), Is.EqualTo("C=Country,L=Locality,O=Organization,OU=Organization Unit,CN=Test CA"));
            Assert.That(() => caCertificateBuilderResult.Certificate.IssuerDN.ToString(), Is.EqualTo("C=Country,L=Locality,O=Organization,OU=Organization Unit,CN=Test CA"));

            Assert.That(() => caCertificateBuilderResult.Certificate.Verify(caCertificateBuilderResult.Certificate.GetPublicKey()), Throws.Nothing);
        }

        [Test]
        public void GenerateCertificateWithRandomSerialNumber()
        {
            var now = DateTime.UtcNow;

            var caCertificateBuilderResult = new CACertificateBuilder()
                .WithRandomSerialNumber()
                .SetKeySize(4096)
                .SetSubjectDN("Test CA", "Organization Unit", "Organization", "Locality", "Country")
                .SetNotBefore(now)
                .SetNotAfter(now.AddMonths(24))
                .Build();

            Assert.That(() => caCertificateBuilderResult, Is.Not.Null);
            Assert.That(() => caCertificateBuilderResult.Certificate, Is.Not.Null);

            Assert.That(() => caCertificateBuilderResult.Certificate.SerialNumber, Is.TypeOf<BigInteger>());

            Assert.That(() => caCertificateBuilderResult.Certificate.SigAlgName, Is.EqualTo("SHA-512withRSA"));

            Assert.That(() => caCertificateBuilderResult.Certificate.NotBefore, Is.EqualTo(now.TruncateMilliseconds()));
            Assert.That(() => caCertificateBuilderResult.Certificate.NotAfter, Is.EqualTo(now.AddMonths(24).TruncateMilliseconds()));

            Assert.That(() => caCertificateBuilderResult.Certificate.IsSelfSigned(), Is.True);

            Assert.That(() => caCertificateBuilderResult.Certificate.SubjectDN.ToString(), Is.EqualTo("C=Country,L=Locality,O=Organization,OU=Organization Unit,CN=Test CA"));
            Assert.That(() => caCertificateBuilderResult.Certificate.IssuerDN.ToString(), Is.EqualTo("C=Country,L=Locality,O=Organization,OU=Organization Unit,CN=Test CA"));

            Assert.That(() => caCertificateBuilderResult.Certificate.Verify(caCertificateBuilderResult.Certificate.GetPublicKey()), Throws.Nothing);
        }
    }
}
