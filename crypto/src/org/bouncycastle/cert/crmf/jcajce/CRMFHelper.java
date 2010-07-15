package org.bouncycastle.cert.crmf.jcajce;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Mac;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.crmf.CRMFException;

abstract class CRMFHelper
{
    protected static final Map DIGEST_ALG_NAMES = new HashMap();
    protected static final Map KEY_ALG_NAMES = new HashMap();
    protected static final Map MAC_ALG_NAMES = new HashMap();

    static
    {
        DIGEST_ALG_NAMES.put(OIWObjectIdentifiers.idSHA1, "SHA1");

        DIGEST_ALG_NAMES.put(NISTObjectIdentifiers.id_sha224, "SHA224");
        DIGEST_ALG_NAMES.put(NISTObjectIdentifiers.id_sha256, "SHA256");
        DIGEST_ALG_NAMES.put(NISTObjectIdentifiers.id_sha384, "SHA384");
        DIGEST_ALG_NAMES.put(NISTObjectIdentifiers.id_sha512, "SHA512");

        MAC_ALG_NAMES.put(PKCSObjectIdentifiers.id_hmacWithSHA1, "HMACSHA1");
        MAC_ALG_NAMES.put(PKCSObjectIdentifiers.id_hmacWithSHA224, "HMACSHA224");
        MAC_ALG_NAMES.put(PKCSObjectIdentifiers.id_hmacWithSHA256, "HMACSHA256");
        MAC_ALG_NAMES.put(PKCSObjectIdentifiers.id_hmacWithSHA384, "HMACSHA384");
        MAC_ALG_NAMES.put(PKCSObjectIdentifiers.id_hmacWithSHA512, "HMACSHA512");

        KEY_ALG_NAMES.put(PKCSObjectIdentifiers.rsaEncryption, "RSA");
        KEY_ALG_NAMES.put(X9ObjectIdentifiers.id_dsa, "DSA");
    }

    PublicKey toPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo)
        throws CRMFException
    {
        X509EncodedKeySpec xspec = new X509EncodedKeySpec(new DERBitString(subjectPublicKeyInfo).getBytes());
        AlgorithmIdentifier keyAlg = subjectPublicKeyInfo.getAlgorithmId();

        try
        {
            return createKeyFactory(keyAlg.getAlgorithm()).generatePublic(xspec);
        }
        catch (InvalidKeySpecException e)
        {
            throw new CRMFException("invalid key: " + e.getMessage(), e);
        }
    }

    KeyFactory createKeyFactory(ASN1ObjectIdentifier algorithm)
        throws CRMFException
    {
        try
        {
            String algName = (String)KEY_ALG_NAMES.get(algorithm);

            if (algName != null)
            {
                try
                {
                    // this is reversed as the Sun policy files now allow unlimited strength RSA
                    return createKeyFactory(algName);
                }
                catch (NoSuchAlgorithmException e)
                {
                    // Ignore
                }
            }
            return createKeyFactory(algorithm.getId());
        }
        catch (GeneralSecurityException e)
        {
            throw new CRMFException("cannot create cipher: " + e.getMessage(), e);
        }
    }

    MessageDigest createDigest(ASN1ObjectIdentifier algorithm)
        throws CRMFException
    {
        try
        {
            String digestName = (String)DIGEST_ALG_NAMES.get(algorithm);

            if (digestName != null)
            {
                try
                {
                    // this is reversed as the Sun policy files now allow unlimited strength RSA
                    return createDigest(digestName);
                }
                catch (NoSuchAlgorithmException e)
                {
                    // Ignore
                }
            }
            return createDigest(algorithm.getId());
        }
        catch (GeneralSecurityException e)
        {
            throw new CRMFException("cannot create cipher: " + e.getMessage(), e);
        }
    }

    Mac createMac(ASN1ObjectIdentifier algorithm)
        throws CRMFException
    {
        try
        {
            String macName = (String)MAC_ALG_NAMES.get(algorithm);

            if (macName != null)
            {
                try
                {
                    // this is reversed as the Sun policy files now allow unlimited strength RSA
                    return createMac(macName);
                }
                catch (NoSuchAlgorithmException e)
                {
                    // Ignore
                }
            }
            return createMac(algorithm.getId());
        }
        catch (GeneralSecurityException e)
        {
            throw new CRMFException("cannot create key pair generator: " + e.getMessage(), e);
        }
    }

    protected abstract KeyFactory createKeyFactory(String algorithm)
            throws GeneralSecurityException;

    protected abstract MessageDigest createDigest(String algorithm)
        throws GeneralSecurityException;

    protected abstract Mac createMac(String algorithm)
        throws GeneralSecurityException;
}
