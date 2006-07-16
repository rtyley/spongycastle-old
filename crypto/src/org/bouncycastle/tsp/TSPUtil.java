package org.bouncycastle.tsp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;

public class TSPUtil
{
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
    
    /**
     * Return the digest algorithm using one of the standard JCA string
     * representations rather the the algorithm identifier (if possible).
     */
    static String getDigestAlgName(
        String digestAlgOID)
    {
        if (PKCSObjectIdentifiers.md5.getId().equals(digestAlgOID))
        {
            return "MD5";
        }
        else if (OIWObjectIdentifiers.idSHA1.getId().equals(digestAlgOID))
        {
            return "SHA1";
        }
        else if (NISTObjectIdentifiers.id_sha224.getId().equals(digestAlgOID))
        {
            return "SHA224";
        }
        else if (NISTObjectIdentifiers.id_sha256.getId().equals(digestAlgOID))
        {
            return "SHA256";
        }
        else if (NISTObjectIdentifiers.id_sha384.getId().equals(digestAlgOID))
        {
            return "SHA384";
        }
        else if (NISTObjectIdentifiers.id_sha512.getId().equals(digestAlgOID))
        {
            return "SHA512";
        }
        else if (PKCSObjectIdentifiers.sha1WithRSAEncryption.getId().equals(digestAlgOID))
        {
            return "SHA1";
        }
        else if (PKCSObjectIdentifiers.sha224WithRSAEncryption.getId().equals(digestAlgOID))
        {
            return "SHA224";
        }
        else if (PKCSObjectIdentifiers.sha256WithRSAEncryption.getId().equals(digestAlgOID))
        {
            return "SHA256";
        }
        else if (PKCSObjectIdentifiers.sha384WithRSAEncryption.getId().equals(digestAlgOID))
        {
            return "SHA384";
        }
        else if (PKCSObjectIdentifiers.sha512WithRSAEncryption.getId().equals(digestAlgOID))
        {
            return "SHA512";
        }
        else if (TeleTrusTObjectIdentifiers.ripemd128.getId().equals(digestAlgOID))
        {
            return "RIPEMD128";
        }
        else if (TeleTrusTObjectIdentifiers.ripemd160.getId().equals(digestAlgOID))
        {
            return "RIPEMD160";
        }
        else if (TeleTrusTObjectIdentifiers.ripemd256.getId().equals(digestAlgOID))
        {
            return "RIPEMD256";
        }
        else if (CryptoProObjectIdentifiers.gostR3411.getId().equals(digestAlgOID))
        {
            return "GOST3411";
        }
        else
        {
            return digestAlgOID;            
        }
    }
}
