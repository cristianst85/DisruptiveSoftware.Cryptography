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

            var certificateBuilderResult = new CACertificateBuilder()
                .SetSerialNumber(1)
                .SetKeySize(2048)
                .SetSubjectDN("Test CA", "Organization Unit", "Organization", "Locality", "Country")
                .SetNotBefore(now)
                .SetNotAfter(now.AddMonths(24))
                .Build();

            Assert.That(() => certificateBuilderResult, Is.Not.Null);
            Assert.That(() => certificateBuilderResult.Certificate, Is.Not.Null);

            Assert.That(() => certificateBuilderResult.Certificate.SerialNumber, Is.EqualTo(BigInteger.One));

            Assert.That(() => certificateBuilderResult.Certificate.SigAlgName, Is.EqualTo("SHA-256withRSA"));

            Assert.That(() => certificateBuilderResult.Certificate.NotBefore, Is.EqualTo(now.TruncateMilliseconds()));
            Assert.That(() => certificateBuilderResult.Certificate.NotAfter, Is.EqualTo(now.AddMonths(24).TruncateMilliseconds()));

            Assert.That(() => certificateBuilderResult.Certificate.IsSelfSigned(), Is.True);

            Assert.That(() => certificateBuilderResult.Certificate.SubjectDN.ToString(), Is.EqualTo("C=Country,L=Locality,O=Organization,OU=Organization Unit,CN=Test CA"));
            Assert.That(() => certificateBuilderResult.Certificate.IssuerDN.ToString(), Is.EqualTo("C=Country,L=Locality,O=Organization,OU=Organization Unit,CN=Test CA"));

            Assert.That(() => certificateBuilderResult.Certificate.Verify(certificateBuilderResult.Certificate.GetPublicKey()), Throws.Nothing);
        }

        [Test]
        public void GenerateCertificateWithRandomSerialNumber()
        {
            var now = DateTime.UtcNow;

            var certificateBuilderResult = new CACertificateBuilder()
                .WithRandomSerialNumber()
                .SetKeySize(2048)
                .SetSubjectDN("Test CA", "Organization Unit", "Organization", "Locality", "Country")
                .SetNotBefore(now)
                .SetNotAfter(now.AddMonths(24))
                .Build();

            Assert.That(() => certificateBuilderResult, Is.Not.Null);
            Assert.That(() => certificateBuilderResult.Certificate, Is.Not.Null);

            Assert.That(() => certificateBuilderResult.Certificate.SerialNumber, Is.TypeOf<BigInteger>());

            Assert.That(() => certificateBuilderResult.Certificate.SigAlgName, Is.EqualTo("SHA-256withRSA"));

            Assert.That(() => certificateBuilderResult.Certificate.NotBefore, Is.EqualTo(now.TruncateMilliseconds()));
            Assert.That(() => certificateBuilderResult.Certificate.NotAfter, Is.EqualTo(now.AddMonths(24).TruncateMilliseconds()));

            Assert.That(() => certificateBuilderResult.Certificate.IsSelfSigned(), Is.True);

            Assert.That(() => certificateBuilderResult.Certificate.SubjectDN.ToString(), Is.EqualTo("C=Country,L=Locality,O=Organization,OU=Organization Unit,CN=Test CA"));
            Assert.That(() => certificateBuilderResult.Certificate.IssuerDN.ToString(), Is.EqualTo("C=Country,L=Locality,O=Organization,OU=Organization Unit,CN=Test CA"));

            Assert.That(() => certificateBuilderResult.Certificate.Verify(certificateBuilderResult.Certificate.GetPublicKey()), Throws.Nothing);
        }
    }
}
