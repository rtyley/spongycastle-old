package org.bouncycastle.cert;

import java.io.IOException;
import java.io.OutputStream;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.util.Arrays;

/**
 * Holding class for an X.509 CRL structure.
 */
public class X509CRLHolder
{
    private CertificateList x509CRL;
    private X509Extensions extensions;

    private static CertificateList parseBytes(byte[] crlEncoding)
        throws IOException
    {
        try
        {
            return CertificateList.getInstance(ASN1Object.fromByteArray(crlEncoding));
        }
        catch (ClassCastException e)
        {
            throw new CertIOException("malformed data: " + e.getMessage(), e);
        }
        catch (IllegalArgumentException e)
        {
            throw new CertIOException("malformed data: " + e.getMessage(), e);
        }
    }

    /**
     * Create a X509CRLHolder from the passed in bytes.
     *
     * @param crlEncoding BER/DER encoding of the CRL
     * @throws IOException in the event of corrupted data, or an incorrect structure.
     */
    public X509CRLHolder(byte[] crlEncoding)
        throws IOException
    {
        this(parseBytes(crlEncoding));
    }

    /**
     * Create a X509CRLHolder from the passed in ASN.1 structure.
     *
     * @param x509CRL an ASN.1 CertificateList structure.
     */
    public X509CRLHolder(CertificateList x509CRL)
    {
        this.x509CRL = x509CRL;
        this.extensions = x509CRL.getTBSCertList().getExtensions();
    }

    public byte[] getEncoded()
        throws IOException
    {
        return x509CRL.getEncoded();
    }

    /**
     * Return whether or not the holder's CRL contains extensions.
     *
     * @return true if extension are present, false otherwise.
     */
    public boolean hasExtensions()
    {
        return extensions != null;
    }

    /**
     * Look up the extension associated with the passed in OID.
     *
     * @param oid the OID of the extension of interest.
     *
     * @return the extension if present, null otherwise.
     */
    public X509Extension getExtension(ASN1ObjectIdentifier oid)
    {
        if (extensions != null)
        {
            return extensions.getExtension(oid);
        }

        return null;
    }

    /**
     * Returns a list of ASN1ObjectIdentifier objects representing the OIDs of the
     * extensions contained in this holder's CRL.
     *
     * @return a list of extension OIDs.
     */
    public List getExtensionOIDs()
    {
        return CertUtils.getExtensionOIDs(extensions);
    }

    /**
     * Returns a set of ASN1ObjectIdentifier objects representing the OIDs of the
     * critical extensions contained in this holder's CRL.
     *
     * @return a set of critical extension OIDs.
     */
    public Set getCriticalExtensionOIDs()
    {
        return CertUtils.getCriticalExtensionOIDs(extensions);
    }

    /**
     * Returns a set of ASN1ObjectIdentifier objects representing the OIDs of the
     * non-critical extensions contained in this holder's CRL.
     *
     * @return a set of non-critical extension OIDs.
     */
    public Set getNonCriticalExtensionOIDs()
    {
        return CertUtils.getNonCriticalExtensionOIDs(extensions);
    }

    public CertificateList toASN1Structure()
    {
        return x509CRL;
    }

    /**
     * Validate the signature on the CRL.
     *
     * @param verifierProvider a ContentVerifierProvider that can generate a verifier for the signature.
     * @return true if the signature is valid, false otherwise.
     * @throws CertException if the signature cannot be processed or is inappropriate.
     */
    public boolean isSignatureValid(ContentVerifierProvider verifierProvider)
        throws CertException
    {
        TBSCertList tbsCRL = x509CRL.getTBSCertList();

        if (!tbsCRL.getSignature().equals(x509CRL.getSignatureAlgorithm()))
        {
            throw new CertException("signature invalid - algorithm identifier mismatch");
        }

        ContentVerifier verifier;

        try
        {
            verifier = verifierProvider.get((tbsCRL.getSignature()));

            OutputStream sOut = verifier.getOutputStream();

            sOut.write(tbsCRL.getDEREncoded());

            sOut.close();
        }
        catch (Exception e)
        {
            throw new CertException("unable to process signature: " + e.getMessage(), e);
        }

        return verifier.verify(x509CRL.getSignature().getBytes());
    }

    public boolean equals(
        Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof X509CRLHolder))
        {
            return false;
        }

        X509CRLHolder other = (X509CRLHolder)o;

        try
        {
            byte[] b1 = this.getEncoded();
            byte[] b2 = other.getEncoded();

            return Arrays.areEqual(b1, b2);
        }
        catch (IOException e)
        {
            return false;
        }
    }

    public int hashCode()
    {
        try
        {
            return Arrays.hashCode(this.getEncoded());
        }
        catch (IOException e)
        {
            return 0;
        }
    }
}
