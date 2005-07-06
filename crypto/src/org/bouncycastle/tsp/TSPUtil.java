package org.bouncycastle.tsp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;

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
}
