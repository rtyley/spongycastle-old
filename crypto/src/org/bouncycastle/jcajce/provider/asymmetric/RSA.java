package org.bouncycastle.jcajce.provider.asymmetric;

import java.util.HashMap;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.RSAUtil;

public class RSA
{
    public static class Mappings
        extends HashMap
    {
        public Mappings()
        {
            put("AlgorithmParameters.OAEP", "org.bouncycastle.jcajce.provider.asymmetric.rsa.AlgorithmParameters$OAEP");
            put("AlgorithmParameters.PSS", "org.bouncycastle.jcajce.provider.asymmetric.rsa.AlgorithmParameters$PSS");

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

            put("Cipher.RSA", "org.bouncycastle.jcajce.provider.asymmetric.rsa.Cipher$NoPadding");
            put("Cipher.RSA/RAW", "org.bouncycastle.jcajce.provider.asymmetric.rsa.Cipher$NoPadding");
            put("Cipher.RSA/PKCS1", "org.bouncycastle.jcajce.provider.asymmetric.rsa.Cipher$PKCS1v1_5Padding");
            put("Cipher.1.2.840.113549.1.1.1", "org.bouncycastle.jcajce.provider.asymmetric.rsa.Cipher$PKCS1v1_5Padding");
            put("Cipher.2.5.8.1.1", "org.bouncycastle.jcajce.provider.asymmetric.rsa.Cipher$PKCS1v1_5Padding");
            put("Cipher.RSA/1", "org.bouncycastle.jcajce.provider.asymmetric.rsa.Cipher$PKCS1v1_5Padding_PrivateOnly");
            put("Cipher.RSA/2", "org.bouncycastle.jcajce.provider.asymmetric.rsa.Cipher$PKCS1v1_5Padding_PublicOnly");
            put("Cipher.RSA/OAEP", "org.bouncycastle.jcajce.provider.asymmetric.rsa.Cipher$OAEPPadding");
            put("Cipher." + PKCSObjectIdentifiers.id_RSAES_OAEP, "org.bouncycastle.jcajce.provider.asymmetric.rsa.Cipher$OAEPPadding");
            put("Cipher.RSA/ISO9796-1", "org.bouncycastle.jcajce.provider.asymmetric.rsa.Cipher$ISO9796d1Padding");

            put("Alg.Alias.Cipher.RSA//RAW", "RSA");
            put("Alg.Alias.Cipher.RSA//NOPADDING", "RSA");
            put("Alg.Alias.Cipher.RSA//PKCS1PADDING", "RSA/PKCS1");
            put("Alg.Alias.Cipher.RSA//OAEPPADDING", "RSA/OAEP");
            put("Alg.Alias.Cipher.RSA//ISO9796-1PADDING", "RSA/ISO9796-1");

            put("KeyFactory.RSA", "org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyFactory");
            for (int i = 0; i != RSAUtil.rsaOids.length; i++)
            {
                addKeyFactory(RSAUtil.rsaOids[i]);
            }

            put("KeyPairGenerator.RSA", "org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyPairGenerator");
            for (int i = 0; i != RSAUtil.rsaOids.length; i++)
            {
                addKeyPairGenerator(RSAUtil.rsaOids[i]);
            }

            put("Signature.SHA1withRSA/ISO9796-2", "org.bouncycastle.jcajce.provider.asymmetric.rsa.ISOSignature$SHA1WithRSAEncryption");
            put("Signature.MD5withRSA/ISO9796-2", "org.bouncycastle.jcajce.provider.asymmetric.rsa.ISOSignature$MD5WithRSAEncryption");
            put("Signature.RIPEMD160withRSA/ISO9796-2", "org.bouncycastle.jcajce.provider.asymmetric.rsa.ISOSignature$RIPEMD160WithRSAEncryption");

            put("Signature.RSASSA-PSS", "org.bouncycastle.jcajce.provider.asymmetric.rsa.PSSSigner$PSSwithRSA");
            put("Signature." + PKCSObjectIdentifiers.id_RSASSA_PSS, "org.bouncycastle.jcajce.provider.asymmetric.rsa.PSSSigner$PSSwithRSA");
            put("Signature.OID." + PKCSObjectIdentifiers.id_RSASSA_PSS, "org.bouncycastle.jcajce.provider.asymmetric.rsa.PSSSigner$PSSwithRSA");
            put("Signature.SHA1withRSA/PSS", "org.bouncycastle.jcajce.provider.asymmetric.rsa.PSSSigner$SHA1withRSA");
            put("Signature.SHA224withRSA/PSS", "org.bouncycastle.jcajce.provider.asymmetric.rsa.PSSSigner$SHA224withRSA");
            put("Signature.SHA256withRSA/PSS", "org.bouncycastle.jcajce.provider.asymmetric.rsa.PSSSigner$SHA256withRSA");
            put("Signature.SHA384withRSA/PSS", "org.bouncycastle.jcajce.provider.asymmetric.rsa.PSSSigner$SHA384withRSA");
            put("Signature.SHA512withRSA/PSS", "org.bouncycastle.jcajce.provider.asymmetric.rsa.PSSSigner$SHA512withRSA");

            put("Signature.RSA", "org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSigner$noneRSA");
            put("Signature.RAWRSASSA-PSS", "org.bouncycastle.jcajce.provider.asymmetric.rsa.PSSSigner$nonePSS");

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

            addDigestSignature("MD2", "org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSigner$MD2", PKCSObjectIdentifiers.md2WithRSAEncryption);
            addDigestSignature("MD4", "org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSigner$MD4", PKCSObjectIdentifiers.md4WithRSAEncryption);
            addDigestSignature("MD5", "org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSigner$MD5", PKCSObjectIdentifiers.md5WithRSAEncryption);
            addDigestSignature("SHA1", "org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSigner$SHA1", PKCSObjectIdentifiers.sha1WithRSAEncryption);

            put("Alg.Alias.Signature." + OIWObjectIdentifiers.sha1WithRSA, "SHA1WITHRSA");
            put("Alg.Alias.Signature.OID." + OIWObjectIdentifiers.sha1WithRSA, "SHA1WITHRSA");

            addDigestSignature("SHA224", "org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSigner$SHA224", PKCSObjectIdentifiers.sha224WithRSAEncryption);
            addDigestSignature("SHA256", "org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSigner$SHA256", PKCSObjectIdentifiers.sha256WithRSAEncryption);
            addDigestSignature("SHA384", "org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSigner$SHA384", PKCSObjectIdentifiers.sha384WithRSAEncryption);
            addDigestSignature("SHA512", "org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSigner$SHA512", PKCSObjectIdentifiers.sha512WithRSAEncryption);

            addDigestSignature("RIPEMD128", "org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSigner$RIPEMD128", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
            addDigestSignature("RIPEMD160", "org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSigner$RIPEMD160", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
            addDigestSignature("RIPEMD256", "org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSigner$RIPEMD256", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);

            addDigestSignature("RMD128", "org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSigner$RIPEMD128", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
            addDigestSignature("RMD160", "org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSigner$RIPEMD160", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
            addDigestSignature("RMD256", "org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSigner$RIPEMD256", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);
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

        private void addKeyFactory(ASN1ObjectIdentifier oid)
        {
            put("Alg.Alias.KeyFactory." + oid, "RSA");
            X509.registerKeyFactory(oid, new KeyFactory());
        }

        private void addKeyPairGenerator(ASN1ObjectIdentifier oid)
        {
            put("Alg.Alias.KeyPairGenerator." + oid, "RSA");
        }
    }
}
