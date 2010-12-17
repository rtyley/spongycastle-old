package org.bouncycastle.cert;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AttCertValidityPeriod;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.AttributeCertificateInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.util.Arrays;

/**
 * Holding class for an X.509 AttributeCertificate structure.
 */
public class X509AttributeCertificateHolder
{
    private AttributeCertificate attrCert;
    private X509Extensions extensions;

    private static AttributeCertificate parseBytes(byte[] certEncoding)
        throws IOException
    {
        try
        {
            return AttributeCertificate.getInstance(ASN1Object.fromByteArray(certEncoding));
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
     * Create a X509AttributeCertificateHolder from the passed in bytes.
     *
     * @param certEncoding BER/DER encoding of the certificate.
     * @throws IOException in the event of corrupted data, or an incorrect structure.
     */
    public X509AttributeCertificateHolder(byte[] certEncoding)
        throws IOException
    {
        this(parseBytes(certEncoding));
    }

    /**
     * Create a X509AttributeCertificateHolder from the passed in ASN.1 structure.
     *
     * @param attrCert an ASN.1 AttributeCertificate structure.
     */
    public X509AttributeCertificateHolder(AttributeCertificate attrCert)
    {
        this.attrCert = attrCert;
        this.extensions = attrCert.getAcinfo().getExtensions();
    }

    public byte[] getEncoded()
        throws IOException
    {
        return attrCert.getEncoded();
    }

    public int getVersion()
    {
        return attrCert.getAcinfo().getVersion().getValue().intValue() + 1;
    }

    public BigInteger getSerialNumber()
    {
        return attrCert.getAcinfo().getSerialNumber().getValue();
    }

    public AttributeCertificateHolder getHolder()
    {
        return new AttributeCertificateHolder((ASN1Sequence)attrCert.getAcinfo().getHolder().toASN1Object());
    }

    public AttributeCertificateIssuer getIssuer()
    {
        return new AttributeCertificateIssuer(attrCert.getAcinfo().getIssuer());
    }

    public Date getNotBefore()
    {
        return CertUtils.recoverDate(attrCert.getAcinfo().getAttrCertValidityPeriod().getNotBeforeTime());
    }

    public Date getNotAfter()
    {
        return CertUtils.recoverDate(attrCert.getAcinfo().getAttrCertValidityPeriod().getNotAfterTime());
    }

    public Attribute[] getAttributes()
    {
        ASN1Sequence seq = attrCert.getAcinfo().getAttributes();
        Attribute[] attrs = new Attribute[seq.size()];

        for (int i = 0; i != seq.size(); i++)
        {
            attrs[i] = Attribute.getInstance(seq.getObjectAt(i));
        }

        return attrs;
    }

    public Attribute[] getAttributes(ASN1ObjectIdentifier oid)
    {
        ASN1Sequence    seq = attrCert.getAcinfo().getAttributes();
        List            list = new ArrayList();

        for (int i = 0; i != seq.size(); i++)
        {
            Attribute attr = Attribute.getInstance(seq.getObjectAt(i));
            if (attr.getAttrType().equals(oid))
            {
                list.add(attr);
            }
        }

        if (list.size() == 0)
        {
            return null;
        }

        return (Attribute[])list.toArray(new Attribute[list.size()]);
    }

    /**
     * Return whether or not the holder's attribute certificate contains extensions.
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
     * extensions contained in this holder's attribute certificate.
     *
     * @return a list of extension OIDs.
     */
    public List getExtensionOIDs()
    {
        return CertUtils.getExtensionOIDs(extensions);
    }

    /**
     * Returns a set of ASN1ObjectIdentifier objects representing the OIDs of the
     * critical extensions contained in this holder's attribute certificate.
     *
     * @return a set of critical extension OIDs.
     */
    public Set getCriticalExtensionOIDs()
    {
        return CertUtils.getCriticalExtensionOIDs(extensions);
    }

    /**
     * Returns a set of ASN1ObjectIdentifier objects representing the OIDs of the
     * non-critical extensions contained in this holder's attribute certificate.
     *
     * @return a set of non-critical extension OIDs.
     */
    public Set getNonCriticalExtensionOIDs()
    {
        return CertUtils.getNonCriticalExtensionOIDs(extensions);
    }

    public boolean[] getIssuerUniqueID()
    {
        return CertUtils.bitStringToBoolean(attrCert.getAcinfo().getIssuerUniqueID());
    }

    public byte[] getSignature()
    {
        return attrCert.getSignatureValue().getBytes();
    }

    public AttributeCertificate toASN1Structure()
    {
        return attrCert;
    }

    public boolean isValidOn(Date date)
    {
        AttCertValidityPeriod certValidityPeriod = attrCert.getAcinfo().getAttrCertValidityPeriod();

        return !date.before(CertUtils.recoverDate(certValidityPeriod.getNotBeforeTime())) && !date.after(CertUtils.recoverDate(certValidityPeriod.getNotAfterTime()));
    }

    public boolean isSignatureValid(ContentVerifierProvider verifierProvider)
        throws CertException
    {
        AttributeCertificateInfo acinfo = attrCert.getAcinfo();

        if (!acinfo.getSignature().equals(attrCert.getSignatureAlgorithm()))
        {
            throw new CertException("signature invalid - algorithm identifier mismatch");
        }

        ContentVerifier verifier;

        try
        {
            verifier = verifierProvider.get((acinfo.getSignature()));

            OutputStream sOut = verifier.getOutputStream();

            sOut.write(acinfo.getDEREncoded());

            sOut.close();
        }
        catch (Exception e)
        {
            throw new CertException("unable to process signature: " + e.getMessage(), e);
        }

        return verifier.verify(attrCert.getSignatureValue().getBytes());
    }

    public boolean equals(
        Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof X509AttributeCertificateHolder))
        {
            return false;
        }

        X509AttributeCertificateHolder other = (X509AttributeCertificateHolder)o;

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
