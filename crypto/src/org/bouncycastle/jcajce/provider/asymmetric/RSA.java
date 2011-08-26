package org.bouncycastle.jcajce.provider.asymmetric;

import java.util.HashMap;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.RSAUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.BCKeyFactory;

public class RSA
{
    private static final String PREFIX = RSA.class.getPackage().getName() + ".rsa.";

    public static class Mappings
        extends HashMap
    {
        public Mappings()
        {
            put("AlgorithmParameters.OAEP", PREFIX + "AlgorithmParametersSpi$OAEP");
            put("AlgorithmParameters.PSS", PREFIX + "AlgorithmParametersSpi$PSS");

            put("Alg.Alias.AlgorithmParameters." + PKCSObjectIdentifiers.id_RSAES_OAEP, "OAEP");

            put("Alg.Alias.AlgorithmParameters.RSAPSS", "PSS");
            put("Alg.Alias.AlgorithmParameters.RSASSA-PSS", "PSS");
            put("Alg.Alias.AlgorithmParameters." + PKCSObjectIdentifiers.id_RSASSA_PSS, "PSS");
            put("Alg.Alias.AlgorithmParameters.SHA1withRSA/PSS", "PSS");
            put("Alg.Alias.AlgorithmParameters.SHA224withRSA/PSS", "PSS");
            put("Alg.Alias.AlgorithmParameters.SHA256withRSA/PSS", "PSS");
            put("Alg.Alias.AlgorithmParameters.SHA384withRSA/PSS", "PSS");
            put("Alg.Alias.AlgorithmParameters.SHA512withRSA/PSS", "PSS");
            put("Alg.Alias.AlgorithmParameters.SHA1WITHRSAANDMGF1", "PSS");
            put("Alg.Alias.AlgorithmParameters.SHA224WITHRSAANDMGF1", "PSS");
            put("Alg.Alias.AlgorithmParameters.SHA256WITHRSAANDMGF1", "PSS");
            put("Alg.Alias.AlgorithmParameters.SHA384WITHRSAANDMGF1", "PSS");
            put("Alg.Alias.AlgorithmParameters.SHA512WITHRSAANDMGF1", "PSS");
            put("Alg.Alias.AlgorithmParameters.RAWRSAPSS", "PSS");
            put("Alg.Alias.AlgorithmParameters.NONEWITHRSAPSS", "PSS");
            put("Alg.Alias.AlgorithmParameters.NONEWITHRSASSA-PSS", "PSS");
            put("Alg.Alias.AlgorithmParameters.NONEWITHRSAANDMGF1", "PSS");

            put("Cipher.RSA", PREFIX + "CipherSpi$NoPadding");
            put("Cipher.RSA/RAW", PREFIX + "CipherSpi$NoPadding");
            put("Cipher.RSA/PKCS1", PREFIX + "CipherSpi$PKCS1v1_5Padding");
            put("Cipher.1.2.840.113549.1.1.1", PREFIX + "CipherSpi$PKCS1v1_5Padding");
            put("Cipher.2.5.8.1.1", PREFIX + "CipherSpi$PKCS1v1_5Padding");
            put("Cipher.RSA/1", PREFIX + "CipherSpi$PKCS1v1_5Padding_PrivateOnly");
            put("Cipher.RSA/2", PREFIX + "CipherSpi$PKCS1v1_5Padding_PublicOnly");
            put("Cipher.RSA/OAEP", PREFIX + "Cipher$OAEPPadding");
            put("Cipher." + PKCSObjectIdentifiers.id_RSAES_OAEP, PREFIX + "CipherSpi$OAEPPadding");
            put("Cipher.RSA/ISO9796-1", PREFIX + "CipherSpi$ISO9796d1Padding");

            put("Alg.Alias.Cipher.RSA//RAW", "RSA");
            put("Alg.Alias.Cipher.RSA//NOPADDING", "RSA");
            put("Alg.Alias.Cipher.RSA//PKCS1PADDING", "RSA/PKCS1");
            put("Alg.Alias.Cipher.RSA//OAEPPADDING", "RSA/OAEP");
            put("Alg.Alias.Cipher.RSA//ISO9796-1PADDING", "RSA/ISO9796-1");

            BCKeyFactory keyFact = new KeyFactorySpi();

            put("KeyFactory.RSA", PREFIX + "KeyFactorySpi");
            for (int i = 0; i != RSAUtil.rsaOids.length; i++)
            {
                addKeyFactory(RSAUtil.rsaOids[i], keyFact);
            }

            put("KeyPairGenerator.RSA", PREFIX + "KeyPairGeneratorSpi");
            for (int i = 0; i != RSAUtil.rsaOids.length; i++)
            {
                addKeyPairGenerator(RSAUtil.rsaOids[i]);
            }

            put("Signature.SHA1withRSA/ISO9796-2", PREFIX + "ISOSignatureSpi$SHA1WithRSAEncryption");
            put("Signature.MD5withRSA/ISO9796-2", PREFIX + "ISOSignatureSpi$MD5WithRSAEncryption");
            put("Signature.RIPEMD160withRSA/ISO9796-2", PREFIX + "ISOSignatureSpi$RIPEMD160WithRSAEncryption");

            put("Signature.RSASSA-PSS", PREFIX + "PSSSignatureSpi$PSSwithRSA");
            put("Signature." + PKCSObjectIdentifiers.id_RSASSA_PSS, PREFIX + "PSSSignatureSpi$PSSwithRSA");
            put("Signature.OID." + PKCSObjectIdentifiers.id_RSASSA_PSS, PREFIX + "PSSSignatureSpi$PSSwithRSA");
            put("Signature.SHA1withRSA/PSS", PREFIX + "PSSSignatureSpi$SHA1withRSA");
            put("Signature.SHA224withRSA/PSS", PREFIX + "PSSSignatureSpi$SHA224withRSA");
            put("Signature.SHA256withRSA/PSS", PREFIX + "PSSSignatureSpi$SHA256withRSA");
            put("Signature.SHA384withRSA/PSS", PREFIX + "PSSSignatureSpi$SHA384withRSA");
            put("Signature.SHA512withRSA/PSS", PREFIX + "PSSSignatureSpi$SHA512withRSA");

            put("Signature.RSA", PREFIX + "DigestSignatureSpi$noneRSA");
            put("Signature.RAWRSASSA-PSS", PREFIX + "PSSSignatureSpi$nonePSS");

            put("Alg.Alias.Signature.RAWRSA", "RSA");
            put("Alg.Alias.Signature.NONEWITHRSA", "RSA");
            put("Alg.Alias.Signature.RAWRSAPSS", "RAWRSASSA-PSS");
            put("Alg.Alias.Signature.NONEWITHRSAPSS", "RAWRSASSA-PSS");
            put("Alg.Alias.Signature.NONEWITHRSASSA-PSS", "RAWRSASSA-PSS");
            put("Alg.Alias.Signature.NONEWITHRSAANDMGF1", "RAWRSASSA-PSS");
            put("Alg.Alias.Signature.RSAPSS", "RSASSA-PSS");

            put("Alg.Alias.Signature.SHA1withRSAandMGF1", "SHA1withRSA/PSS");
            put("Alg.Alias.Signature.SHA224withRSAandMGF1", "SHA224withRSA/PSS");
            put("Alg.Alias.Signature.SHA256withRSAandMGF1", "SHA256withRSA/PSS");
            put("Alg.Alias.Signature.SHA384withRSAandMGF1", "SHA384withRSA/PSS");
            put("Alg.Alias.Signature.SHA512withRSAandMGF1", "SHA512withRSA/PSS");


            put("Alg.Alias.Signature.RMD160withRSA", "RIPEMD160WithRSAEncryption");
            put("Alg.Alias.Signature.RMD160/RSA", "RIPEMD160WithRSAEncryption");
            put("Alg.Alias.Signature.1.3.36.3.3.1.2", "RIPEMD160WithRSAEncryption");
            put("Alg.Alias.Signature.1.3.36.3.3.1.3", "RIPEMD128WithRSAEncryption");
            put("Alg.Alias.Signature.1.3.36.3.3.1.4", "RIPEMD256WithRSAEncryption");

            addDigestSignature("MD2", PREFIX + "DigestSignatureSpi$MD2", PKCSObjectIdentifiers.md2WithRSAEncryption);
            addDigestSignature("MD4", PREFIX + "DigestSignatureSpi$MD4", PKCSObjectIdentifiers.md4WithRSAEncryption);
            addDigestSignature("MD5", PREFIX + "DigestSignatureSpi$MD5", PKCSObjectIdentifiers.md5WithRSAEncryption);
            addDigestSignature("SHA1", PREFIX + "DigestSignatureSpi$SHA1", PKCSObjectIdentifiers.sha1WithRSAEncryption);

            put("Alg.Alias.Signature." + OIWObjectIdentifiers.sha1WithRSA, "SHA1WITHRSA");
            put("Alg.Alias.Signature.OID." + OIWObjectIdentifiers.sha1WithRSA, "SHA1WITHRSA");

            addDigestSignature("SHA224", PREFIX + "DigestSignatureSpi$SHA224", PKCSObjectIdentifiers.sha224WithRSAEncryption);
            addDigestSignature("SHA256", PREFIX + "DigestSignatureSpi$SHA256", PKCSObjectIdentifiers.sha256WithRSAEncryption);
            addDigestSignature("SHA384", PREFIX + "DigestSignatureSpi$SHA384", PKCSObjectIdentifiers.sha384WithRSAEncryption);
            addDigestSignature("SHA512", PREFIX + "DigestSignatureSpi$SHA512", PKCSObjectIdentifiers.sha512WithRSAEncryption);

            addDigestSignature("RIPEMD128", PREFIX + "DigestSignatureSpi$RIPEMD128", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
            addDigestSignature("RIPEMD160", PREFIX + "DigestSignatureSpi$RIPEMD160", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
            addDigestSignature("RIPEMD256", PREFIX + "DigestSignatureSpi$RIPEMD256", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);

            addDigestSignature("RMD128", PREFIX + "DigestSignatureSpi$RIPEMD128", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
            addDigestSignature("RMD160", PREFIX + "DigestSignatureSpi$RIPEMD160", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
            addDigestSignature("RMD256", PREFIX + "DigestSignatureSpi$RIPEMD256", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);
        }

        private void addDigestSignature(
            String digest,
            String className,
            ASN1ObjectIdentifier oid)
        {
            String mainName = digest + "WITHRSA";
            String jdk11Variation1 = digest + "withRSA";
            String jdk11Variation2 = digest + "WithRSA";
            String alias = digest + "/" + "RSA";
            String longName = digest + "WITHRSAENCRYPTION";
            String longJdk11Variation1 = digest + "withRSAEncryption";
            String longJdk11Variation2 = digest + "WithRSAEncryption";

            put("Signature." + mainName, className);
            put("Alg.Alias.Signature." + jdk11Variation1, mainName);
            put("Alg.Alias.Signature." + jdk11Variation2, mainName);
            put("Alg.Alias.Signature." + longName, mainName);
            put("Alg.Alias.Signature." + longJdk11Variation1, mainName);
            put("Alg.Alias.Signature." + longJdk11Variation2, mainName);
            put("Alg.Alias.Signature." + alias, mainName);
            put("Alg.Alias.Signature." + oid, mainName);
            put("Alg.Alias.Signature.OID." + oid, mainName);
        }

        private void addKeyFactory(ASN1ObjectIdentifier oid, BCKeyFactory keyFactory)
        {
            put("Alg.Alias.KeyFactory." + oid, "RSA");
            X509.registerKeyFactory(oid, keyFactory);
        }

        private void addKeyPairGenerator(ASN1ObjectIdentifier oid)
        {
            put("Alg.Alias.KeyPairGenerator." + oid, "RSA");
        }
    }
}
