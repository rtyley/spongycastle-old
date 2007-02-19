package org.bouncycastle.tsp;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extensions;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public class TSPUtil
{
    private static final Map digestLengths = new HashMap();
    private static final Map digestNames = new HashMap();

    static
    {
        digestLengths.put(PKCSObjectIdentifiers.md5.getId(), new Integer(16));
        digestLengths.put(OIWObjectIdentifiers.idSHA1.getId(), new Integer(20));
        digestLengths.put(NISTObjectIdentifiers.id_sha224.getId(), new Integer(28));
        digestLengths.put(NISTObjectIdentifiers.id_sha256.getId(), new Integer(32));
        digestLengths.put(NISTObjectIdentifiers.id_sha384.getId(), new Integer(48));
        digestLengths.put(NISTObjectIdentifiers.id_sha512.getId(), new Integer(64));

        digestNames.put(PKCSObjectIdentifiers.md5.getId(), "MD5");
        digestNames.put(OIWObjectIdentifiers.idSHA1.getId(), "SHA1");
        digestNames.put(NISTObjectIdentifiers.id_sha224.getId(), "SHA224");
        digestNames.put(NISTObjectIdentifiers.id_sha256.getId(), "SHA256");
        digestNames.put(NISTObjectIdentifiers.id_sha384.getId(), "SHA384");
        digestNames.put(NISTObjectIdentifiers.id_sha512.getId(), "SHA512");
        digestNames.put(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), "SHA1");
        digestNames.put(PKCSObjectIdentifiers.sha224WithRSAEncryption.getId(), "SHA224");
        digestNames.put(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), "SHA256");
        digestNames.put(PKCSObjectIdentifiers.sha384WithRSAEncryption.getId(), "SHA384");
        digestNames.put(PKCSObjectIdentifiers.sha512WithRSAEncryption.getId(), "SHA512");
        digestNames.put(TeleTrusTObjectIdentifiers.ripemd128.getId(), "RIPEMD128");
        digestNames.put(TeleTrusTObjectIdentifiers.ripemd160.getId(), "RIPEMD160");
        digestNames.put(TeleTrusTObjectIdentifiers.ripemd256.getId(), "RIPEMD256");
        digestNames.put(CryptoProObjectIdentifiers.gostR3411.getId(), "GOST3411");
    }
    
    /**
     * Validate the passed in certificate as being of the correct type to be used
     * for time stamping. To be valid it must have an ExtendedKeyUsage extension
     * which has a key purpose identifier of id-kp-timeStamping.
     * 
     * @param cert the certificate of interest.
     * @throws TSPValidationException if the certicate fails on one of the check points.
     */
    public static void validateCertificate(
        X509Certificate cert)
        throws TSPValidationException
    {
        if (cert.getVersion() != 3)
        {
            throw new IllegalArgumentException("Certificate must have an ExtendedKeyUsage extension.");
        }
        
        byte[]  ext = cert.getExtensionValue(X509Extensions.ExtendedKeyUsage.getId());
        if (ext == null)
        {
            throw new TSPValidationException("Certificate must have an ExtendedKeyUsage extension.");
        }
        
        if (!cert.getCriticalExtensionOIDs().contains(X509Extensions.ExtendedKeyUsage.getId()))
        {
            throw new TSPValidationException("Certificate must have an ExtendedKeyUsage extension marked as critical.");
        }

        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(ext));

        try
        {
            aIn = new ASN1InputStream(new ByteArrayInputStream(((ASN1OctetString)aIn.readObject()).getOctets()));
            
            ExtendedKeyUsage    extKey = ExtendedKeyUsage.getInstance(aIn.readObject());
            
            if (!extKey.hasKeyPurposeId(KeyPurposeId.id_kp_timeStamping) || extKey.size() != 1)
            {
                throw new TSPValidationException("ExtendedKeyUsage not solely time stamping.");
            }
        }
        catch (IOException e)
        {
            throw new TSPValidationException("cannot process ExtendedKeyUsage extension");
        }
    }
    
    /*
     * Return the digest algorithm using one of the standard JCA string
     * representations rather than the algorithm identifier (if possible).
     */
    static String getDigestAlgName(
        String digestAlgOID)
    {
        String digestName = (String)digestNames.get(digestAlgOID);

        if (digestName != null)
        {
            return digestName;
        }

        return digestAlgOID;
    }

    static int getDigestLength(
        String digestAlgOID,
        String provider)
        throws NoSuchProviderException, TSPException
    {
        String digestName = TSPUtil.getDigestAlgName(digestAlgOID);

        try
        {
            Integer length = (Integer)digestLengths.get(digestAlgOID);

            if (length != null)
            {
                return length.intValue();
            }
            
            return MessageDigest.getInstance(digestName, provider).getDigestLength();
        }
        catch (NoSuchAlgorithmException e)
        {
            try
            {
                return MessageDigest.getInstance(digestName).getDigestLength();
            }
            catch (NoSuchAlgorithmException ex)
            {
                throw new TSPException("digest algorithm cannot be found.", ex);
            }
        }
    }
}
