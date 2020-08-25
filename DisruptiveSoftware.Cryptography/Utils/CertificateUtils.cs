using DisruptiveSoftware.Cryptography.Extensions;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace DisruptiveSoftware.Cryptography.Utils
{
    public static class CertificateUtils
    {
        public static string ExportPublicKeyToPEM(byte[] certificateData)
        {
            using (var textWriter = new StringWriter())
            {
                var x509CertificateParser = new X509CertificateParser();
                var x509Certificate = x509CertificateParser.ReadCertificate(certificateData);
                var asymmetricKeyParameter = x509Certificate.GetPublicKey();
                var pemWriter = new PemWriter(textWriter);
                pemWriter.WriteObject(asymmetricKeyParameter);

                return pemWriter.Writer.ToString();
            }
        }

        public static string ExportPublicKeyCertificateToPEM(byte[] certificateData)
        {
            using (var textWriter = new StringWriter())
            {
                var x509CertificateParser = new X509CertificateParser();
                var x509Certificate = x509CertificateParser.ReadCertificate(certificateData);
                var pemWriter = new PemWriter(textWriter);
                pemWriter.WriteObject(x509Certificate);

                return pemWriter.Writer.ToString();
            }
        }

        public static string ExportPrivateKeyToPEM(RSACryptoServiceProvider rsaCryptoServiceProvider)
        {
            using (var textWriter = new StringWriter())
            {
                var asymmetricCipherKeyPair = DotNetUtilities.GetRsaKeyPair(rsaCryptoServiceProvider);
                var pemWriter = new PemWriter(textWriter);
                pemWriter.WriteObject(asymmetricCipherKeyPair.Private);

                return pemWriter.Writer.ToString();
            }
        }

        public static byte[] ExportPublicKeyCertificate(byte[] certificateData, SecureString certificatePassword)
        {
            var x509Certificate2 = new X509Certificate2(certificateData, certificatePassword);

            return x509Certificate2.Export(X509ContentType.Cert);
        }

        public static string ExportPublicKeyCertificateToBase64(byte[] certificateData, SecureString certificatePassword)
        {
            return Convert.ToBase64String(ExportPublicKeyCertificate(certificateData, certificatePassword));
        }

        public static string ExportPublicKeyCertificateToPEM(byte[] certificateData, SecureString certificatePassword)
        {
            var stringBuilder = new StringBuilder();

            stringBuilder.AppendLine("-----BEGIN CERTIFICATE-----");
            stringBuilder.AppendLine(Convert.ToBase64String(ExportPublicKeyCertificate(certificateData, certificatePassword), Base64FormattingOptions.InsertLineBreaks));
            stringBuilder.AppendLine("-----END CERTIFICATE-----");

            return stringBuilder.ToString();
        }

        public static string ExportPrivateKeyToPEM(byte[] certificateData, SecureString certificatePassword)
        {
            var x509Certificate2 = new X509Certificate2(
                certificateData,
                certificatePassword,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet
            );

            if (!x509Certificate2.HasPrivateKey)
            {
                return null;
            }

            using (var rsa = x509Certificate2.PrivateKey as RSACryptoServiceProvider)
            {
                return ExportPrivateKeyToPEM(rsa);
            }
        }

        public static byte[] ExportPrivateKey(byte[] certificateData, SecureString certificatePassword)
        {
            var privateKey = ExportPrivateKeyToPEM(certificateData, certificatePassword);
            
            // Certificate does not have a private key.
            if (privateKey.IsNullOrEmpty())
            {
                return null;
            }

            var stringBuilder = new StringBuilder();

            foreach (var pemLine in privateKey.Split('\n'))
            {
                // Trim padding CR and white spaces.
                var line = pemLine.TrimEnd('\r').Trim();

                // Skip directives and empty lines.
                if (!(line.Contains("BEGIN RSA PRIVATE KEY") || line.Contains("END RSA PRIVATE KEY") || line.Length == 0))
                {
                    stringBuilder.Append(line);
                }
            }

            // Decode Base64 to DER.
            return Convert.FromBase64String(stringBuilder.ToString());
        }

        public static string ExportPrivateKeyAsXMLString(byte[] certificateData, SecureString certificatePassword)
        {
            var x509Certificate2 = new X509Certificate2(
                 certificateData,
                 certificatePassword,
                 X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet
             );

            using (var rsa = x509Certificate2.PrivateKey as RSA)
            {
                return rsa.ToXmlString(true);
            }
        }
    }
}
