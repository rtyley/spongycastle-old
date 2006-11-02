package org.bouncycastle.cms;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.util.HashMap;
import java.util.Map;

class CMSSignedHelper
{
    static final CMSSignedHelper INSTANCE = new CMSSignedHelper();

    private static final Map     encryptionAlgs = new HashMap();
    private static final Map     digestAlgs = new HashMap();


    static
    {
        encryptionAlgs.put(X9ObjectIdentifiers.id_dsa_with_sha1.getId(), "DSA");
        encryptionAlgs.put(X9ObjectIdentifiers.id_dsa.getId(), "DSA");
        encryptionAlgs.put(OIWObjectIdentifiers.dsaWithSHA1.getId(), "DSA");
        encryptionAlgs.put(PKCSObjectIdentifiers.rsaEncryption.getId(), "RSA");
        encryptionAlgs.put(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), "RSA");
        encryptionAlgs.put(TeleTrusTObjectIdentifiers.teleTrusTRSAsignatureAlgorithm, "RSA");
        encryptionAlgs.put(X509ObjectIdentifiers.id_ea_rsa.getId(), "RSA");
        encryptionAlgs.put(CMSSignedDataGenerator.ENCRYPTION_ECDSA, "ECDSA");
        encryptionAlgs.put(X9ObjectIdentifiers.ecdsa_with_SHA2.getId(), "ECDSA");
        encryptionAlgs.put(X9ObjectIdentifiers.ecdsa_with_SHA224.getId(), "ECDSA");
        encryptionAlgs.put(X9ObjectIdentifiers.ecdsa_with_SHA256.getId(), "ECDSA");
        encryptionAlgs.put(X9ObjectIdentifiers.ecdsa_with_SHA384.getId(), "ECDSA");
        encryptionAlgs.put(X9ObjectIdentifiers.ecdsa_with_SHA512.getId(), "ECDSA");
        encryptionAlgs.put(CMSSignedDataGenerator.ENCRYPTION_RSA_PSS, "RSAandMGF1");
        encryptionAlgs.put(CryptoProObjectIdentifiers.gostR3410_94.getId(), "GOST3410");
        encryptionAlgs.put(CryptoProObjectIdentifiers.gostR3410_2001.getId(), "ECGOST3410");
        encryptionAlgs.put("1.3.6.1.4.1.5849.1.6.2", "ECGOST3410");

        digestAlgs.put(PKCSObjectIdentifiers.md5.getId(), "MD5");
        digestAlgs.put(OIWObjectIdentifiers.idSHA1.getId(), "SHA1");
        digestAlgs.put(NISTObjectIdentifiers.id_sha224.getId(), "SHA224");
        digestAlgs.put(NISTObjectIdentifiers.id_sha256.getId(), "SHA256");
        digestAlgs.put(NISTObjectIdentifiers.id_sha384.getId(), "SHA384");
        digestAlgs.put(NISTObjectIdentifiers.id_sha512.getId(), "SHA512");
        digestAlgs.put(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), "SHA1");
        digestAlgs.put(PKCSObjectIdentifiers.sha224WithRSAEncryption.getId(), "SHA224");
        digestAlgs.put(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), "SHA256");
        digestAlgs.put(PKCSObjectIdentifiers.sha384WithRSAEncryption.getId(), "SHA384");
        digestAlgs.put(PKCSObjectIdentifiers.sha512WithRSAEncryption.getId(), "SHA512");
        digestAlgs.put(TeleTrusTObjectIdentifiers.ripemd128.getId(), "RIPEMD128");
        digestAlgs.put(TeleTrusTObjectIdentifiers.ripemd160.getId(), "RIPEMD160");
        digestAlgs.put(TeleTrusTObjectIdentifiers.ripemd256.getId(), "RIPEMD256");
        digestAlgs.put(CryptoProObjectIdentifiers.gostR3411.getId(),  "GOST3411");
        digestAlgs.put("1.3.6.1.4.1.5849.1.2.1",  "GOST3411");
    }
    
    /**
     * Return the digest algorithm using one of the standard JCA string
     * representations rather the the algorithm identifier (if possible).
     */
    String getDigestAlgName(
        String digestAlgOID)
    {
        String algName = (String)digestAlgs.get(digestAlgOID);

        if (algName != null)
        {
            return algName;
        }

        return digestAlgOID;
    }
    
    /**
     * Return the digest encryption algorithm using one of the standard
     * JCA string representations rather the the algorithm identifier (if
     * possible).
     */
    String getEncryptionAlgName(
        String encryptionAlgOID)
    {
        String algName = (String)encryptionAlgs.get(encryptionAlgOID);

        if (algName != null)
        {
            return algName;
        }

        return encryptionAlgOID;
    }
    
    MessageDigest getDigestInstance(
        String algorithm, 
        String provider) 
        throws NoSuchProviderException, NoSuchAlgorithmException
    {
        if (provider != null)
        {
            try
            {
                return MessageDigest.getInstance(algorithm, provider);
            }
            catch (NoSuchAlgorithmException e)
            {
                return MessageDigest.getInstance(algorithm); // try rolling back
            }
        }
        else
        {
            return MessageDigest.getInstance(algorithm);
        }
    }
    
    Signature getSignatureInstance(
        String algorithm, 
        String provider) 
        throws NoSuchProviderException, NoSuchAlgorithmException
    {
        if (provider != null)
        {
            return Signature.getInstance(algorithm, provider);
        }
        else
        {
            return Signature.getInstance(algorithm);
        }
    }
}
