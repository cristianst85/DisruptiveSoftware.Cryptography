using DisruptiveSoftware.Cryptography.BouncyCastle.Extensions;
using DisruptiveSoftware.Cryptography.Extensions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Security;

using SystemX509Certificates = System.Security.Cryptography.X509Certificates;

namespace DisruptiveSoftware.Cryptography.X509
{
    public class SSLCertificateBuilder : X509CertificateBuilder
    {
        protected IList<string> SubjectAlternativeNames { get; private set; }

        protected byte[] IssuerCertificate { get; private set; }
        protected SecureString IssuerCertificatePassword { get; private set; }

        protected bool IsServerAuthKeyUsage { get; private set; }
        protected bool IsClientAuthKeyUsage { get; private set; }

        public new SSLCertificateBuilder SetKeySize(uint keySize)
        {
            base.SetKeySize(keySize);
            return this;
        }

        public new SSLCertificateBuilder SetSerialNumber(long serialNumber)
        {
            base.SetSerialNumber(serialNumber);
            return this;
        }

        public new SSLCertificateBuilder WithRandomSerialNumber()
        {
            base.WithRandomSerialNumber();
            return this;
        }

        public new SSLCertificateBuilder SetNotBefore(DateTime notBefore)
        {
            base.SetNotBefore(notBefore);
            return this;
        }

        public new SSLCertificateBuilder SetNotAfter(DateTime notAfter)
        {
            base.SetNotAfter(notAfter);
            return this;
        }

        public new SSLCertificateBuilder SetSubjectDN(string cn, string ou, string o, string l, string c)
        {
            base.SetSubjectDN(cn, ou, o, l, c);
            return this;
        }

        public SSLCertificateBuilder SetSubjectAlternativeNames(IList<string> subjectAlternativeNames)
        {
            this.SubjectAlternativeNames = new List<string>(subjectAlternativeNames);
            return this;
        }

        public SSLCertificateBuilder SetIssuerCertificate(byte[] issuerCertificate, SecureString issuerCertificatePassword)
        {
            this.IssuerCertificate = issuerCertificate;
            this.IssuerCertificatePassword = issuerCertificatePassword;
            return this;
        }

        public SSLCertificateBuilder SetServerAuthKeyUsage()
        {
            this.IsServerAuthKeyUsage = true;
            return this;
        }

        public SSLCertificateBuilder SetClientAuthKeyUsage()
        {
            this.IsClientAuthKeyUsage = true;
            return this;
        }

        public override X509CertificateBuilderResult Build()
        {
            var issuerX509Certificate2 = new SystemX509Certificates.X509Certificate2(
                IssuerCertificate,
                IssuerCertificatePassword,
                SystemX509Certificates.X509KeyStorageFlags.Exportable
            );

            var issuerSubjectDN = issuerX509Certificate2.ToX509Certificate().SubjectDN;

            X509V3CertificateGenerator.SetIssuerDN(issuerSubjectDN);

            // Generate Keys.
            var rsaKeyPairGenerator = new RsaKeyPairGenerator();
            rsaKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(new CryptoApiRandomGenerator()), this.KeySize));
            var asymmetricCipherKeyPair = rsaKeyPairGenerator.GenerateKeyPair();

            // Set Public Key.
            X509V3CertificateGenerator.SetPublicKey(asymmetricCipherKeyPair.Public);

            // Key Usage - for maximum interoperability, specify all four flags.
            var keyUsage = KeyUsage.DigitalSignature | KeyUsage.NonRepudiation | KeyUsage.KeyEncipherment | KeyUsage.KeyAgreement;

            X509V3CertificateGenerator.AddExtension(
               X509Extensions.KeyUsage,
               true,
               new KeyUsage(keyUsage)
            );

            X509V3CertificateGenerator.AddExtension(
                X509Extensions.BasicConstraints,
                true,
                new BasicConstraints(false)
            );

            // Extended Key Usage.
            var extendedKeyUsage = new List<KeyPurposeID>();

            // Set TLS Web Server Authentication (1.3.6.1.5.5.7.3.1).
            if (IsServerAuthKeyUsage)
            {
                extendedKeyUsage.Add(KeyPurposeID.IdKPServerAuth);
            }

            // Set TLS Web Client Authentication (1.3.6.1.5.5.7.3.2).
            if (IsClientAuthKeyUsage)
            {
                extendedKeyUsage.Add(KeyPurposeID.IdKPClientAuth);
            }

            X509V3CertificateGenerator.AddExtension(
                X509Extensions.ExtendedKeyUsage,
                true,
                new ExtendedKeyUsage(extendedKeyUsage)
            );

            // Set Subject Alternative Names.
            if (SubjectAlternativeNames != null)
            {
                var subjectAlternativeNames = new Asn1Encodable[SubjectAlternativeNames.Count];

                for (int i = 0; i < SubjectAlternativeNames.Count; i++)
                {
                    subjectAlternativeNames[i] = new GeneralName(GeneralName.DnsName, SubjectAlternativeNames[i]);
                }

                X509V3CertificateGenerator.AddExtension(
                    X509Extensions.SubjectAlternativeName,
                    false,
                    new DerSequence(subjectAlternativeNames)
                );
            }

            X509V3CertificateGenerator.AddExtension(
                X509Extensions.AuthorityKeyIdentifier,
                false,
                new AuthorityKeyIdentifier(
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(issuerX509Certificate2.GetPublicKeyAsAsymmetricKeyParameter()),
                    new GeneralNames(new GeneralName(issuerSubjectDN)),
                    new Org.BouncyCastle.Math.BigInteger(issuerX509Certificate2.GetSerialNumber())
                )
            );

            X509V3CertificateGenerator.AddExtension(
                X509Extensions.SubjectKeyIdentifier,
                false,
                new SubjectKeyIdentifier(
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(asymmetricCipherKeyPair.Public)
                )
            );

            var signatureFactory = new Asn1SignatureFactory(GetSignatureAlgorithm(this.KeySize), issuerX509Certificate2.GetPrivateKeyAsAsymmetricKeyParameter());

            // Generate X.509 Certificate.
            var x509Certificate = X509V3CertificateGenerator.Generate(signatureFactory);

            return new X509CertificateBuilderResult(x509Certificate, asymmetricCipherKeyPair.Private);
        }
    }
}
