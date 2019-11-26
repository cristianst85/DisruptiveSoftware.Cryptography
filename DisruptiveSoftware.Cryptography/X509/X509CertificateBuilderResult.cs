using DisruptiveSoftware.Cryptography.BouncyCastle.Extensions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using System.Security;

namespace DisruptiveSoftware.Cryptography.X509
{
    public class X509CertificateBuilderResult
    {
        public X509Certificate Certificate { get; private set; }

        protected AsymmetricKeyParameter PrivateKey { get; private set; }

        public X509CertificateBuilderResult(X509Certificate certificate, AsymmetricKeyParameter privateKey)
        {
            this.Certificate = certificate;
            this.PrivateKey = privateKey;
        }

        public byte[] ExportCertificate(SecureString password, string alias = "Certificate")
        {
            return this.Certificate.ExportCertificate(password, this.PrivateKey, alias);
        }
    }
}
