using DisruptiveSoftware.Cryptography.BouncyCastle.Extensions;
using DisruptiveSoftware.Cryptography.Extensions;
using DisruptiveSoftware.Cryptography.Tests.Extensions;
using NUnit.Framework;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace DisruptiveSoftware.Cryptography.X509.Tests
{
    [TestFixture]
    public class SSLCertificateBuilderTests
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

            var pkcs12Data = certificateBuilderResult.ExportCertificate("12345678".ToSecureString());

            var sslCertificateBuilderResult = new SSLCertificateBuilder()
                .SetSerialNumber(2)
                .SetKeySize(4096)
                .SetSubjectDN("Test SSL", "Organization Unit", "Organization", "Locality", "Country")
                .SetNotBefore(now)
                .SetNotAfter(now.AddMonths(12))
                .SetIssuerCertificate(pkcs12Data, "12345678".ToSecureString())
                .SetClientAuthKeyUsage()
                .SetServerAuthKeyUsage()
                .SetSubjectAlternativeNames(new List<string>() { "example.com" })
                .Build();

            Assert.That(() => sslCertificateBuilderResult, Is.Not.Null);
            Assert.That(() => sslCertificateBuilderResult.Certificate, Is.Not.Null);

            Assert.That(() => sslCertificateBuilderResult.Certificate.SigAlgName, Is.EqualTo("SHA-512withRSA"));

            Assert.That(() => sslCertificateBuilderResult.Certificate.SerialNumber, Is.EqualTo(BigInteger.Two));
            Assert.That(() => sslCertificateBuilderResult.Certificate.NotBefore, Is.EqualTo(now.TruncateMilliseconds()));
            Assert.That(() => sslCertificateBuilderResult.Certificate.NotAfter, Is.EqualTo(now.AddMonths(12).TruncateMilliseconds()));

            Assert.That(() => sslCertificateBuilderResult.Certificate.GetExtendedKeyUsage(), Is.EqualTo(new List<string>() { KeyPurposeID.IdKPServerAuth.Id, KeyPurposeID.IdKPClientAuth.Id }));
            Assert.That(() => sslCertificateBuilderResult.Certificate.GetSubjectAlternativeNames().Cast<ArrayList>().ToList()[0], Is.EqualTo(new ArrayList() { GeneralName.DnsName, "example.com" }));

            Assert.That(() => sslCertificateBuilderResult.Certificate.IsSelfSigned(), Is.False);

            Assert.That(() => sslCertificateBuilderResult.Certificate.SubjectDN.ToString(), Is.EqualTo("C=Country,L=Locality,O=Organization,OU=Organization Unit,CN=Test SSL"));
            Assert.That(() => sslCertificateBuilderResult.Certificate.IssuerDN.ToString(), Is.EqualTo("C=Country,L=Locality,O=Organization,OU=Organization Unit,CN=Test CA"));

            Assert.That(() => sslCertificateBuilderResult.Certificate.Verify(certificateBuilderResult.Certificate.GetPublicKey()), Throws.Nothing);
        }
    }
}
