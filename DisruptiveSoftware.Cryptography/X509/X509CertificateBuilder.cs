using DisruptiveSoftware.Cryptography.Extensions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using System;
using System.Collections;

namespace DisruptiveSoftware.Cryptography.X509
{
    public abstract class X509CertificateBuilder
    {
        protected X509V3CertificateGenerator X509V3CertificateGenerator { get; private set; }

        protected IList AttributesOids { get; private set; }

        protected IList AttributesValues { get; private set; }

        protected int KeySize { get; private set; }

        protected BigInteger SerialNumber { get; private set; }

        public X509CertificateBuilder()
        {
            this.X509V3CertificateGenerator = new X509V3CertificateGenerator();
            this.AttributesOids = new ArrayList();
            this.AttributesValues = new ArrayList();
        }

        public virtual X509CertificateBuilder SetKeySize(uint keySize)
        {
            this.KeySize = (int)keySize;
            return this;
        }

        public virtual X509CertificateBuilder SetSerialNumber(long serialNumber)
        {
            this.SerialNumber = BigInteger.ValueOf(serialNumber);
            X509V3CertificateGenerator.SetSerialNumber(this.SerialNumber);
            return this;
        }

        public virtual X509CertificateBuilder WithRandomSerialNumber()
        {
            this.SerialNumber = GetRandomSerialNumber();
            X509V3CertificateGenerator.SetSerialNumber(this.SerialNumber);
            return this;
        }

        public virtual X509CertificateBuilder SetSubjectDN(string cn, string ou, string o, string l, string c)
        {
            var result = BuildX509Name(cn, ou, o, l, c);

            this.AttributesOids = result.Item1;
            this.AttributesValues = result.Item2;

            X509V3CertificateGenerator.SetSubjectDN(new X509Name(result.Item1, result.Item2));

            return this;
        }

        protected Tuple<IList, IList> BuildX509Name(string cn, string ou, string o, string l, string c)
        {
            IList attributesOids = new ArrayList();
            IList attributesValues = new ArrayList();

            if (!c.IsNullOrEmpty())
            {
                AddAttribute(X509Name.C, c, attributesOids, attributesValues);
            }

            if (!l.IsNullOrEmpty())
            {
                AddAttribute(X509Name.L, l, attributesOids, attributesValues);
            }

            if (!o.IsNullOrEmpty())
            {
                AddAttribute(X509Name.O, o, attributesOids, attributesValues);
            }

            if (!ou.IsNullOrEmpty())
            {
                AddAttribute(X509Name.OU, ou, attributesOids, attributesValues);
            }

            if (!cn.IsNullOrEmpty())
            {
                AddAttribute(X509Name.CN, cn, attributesOids, attributesValues);
            }

            return new Tuple<IList, IList>(attributesOids, attributesValues);
        }

        private void AddAttribute(DerObjectIdentifier oid, string value, IList attributesOids, IList attributesValues)
        {
            attributesOids.Add(oid);
            attributesValues.Add(value);
        }

        protected string GetSignatureAlgorithm(int keySize)
        {
            if (keySize == Constants.RSAKeySize.KeySize1024)
            {
                return Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.Sha1WithRsaEncryption.Id;
            }
            else if (keySize == Constants.RSAKeySize.KeySize2048)
            {
                return Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id;
            }
            else if (keySize == Constants.RSAKeySize.KeySize3072)
            {
                return Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.Sha384WithRsaEncryption.Id;
            }
            else if (keySize == Constants.RSAKeySize.KeySize4096)
            {
                return Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.Sha512WithRsaEncryption.Id;
            }
            else
            {
                throw new Exception(string.Format("Unable to determine signature algorithm. Invalid private key size {0}.", keySize));
            }
        }

        protected BigInteger GetRandomSerialNumber()
        {
            return BigIntegers.CreateRandomInRange(
                BigInteger.One,
                BigInteger.ValueOf(long.MaxValue),
                new SecureRandom(new CryptoApiRandomGenerator())
            );
        }

        public virtual X509CertificateBuilder SetNotBefore(DateTime notBefore)
        {
            X509V3CertificateGenerator.SetNotBefore(notBefore);
            return this;
        }

        public virtual X509CertificateBuilder SetNotAfter(DateTime notAfter)
        {
            X509V3CertificateGenerator.SetNotAfter(notAfter);
            return this;
        }

        public abstract X509CertificateBuilderResult Build();
    }
}
