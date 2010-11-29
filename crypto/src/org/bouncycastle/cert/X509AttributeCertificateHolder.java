package org.bouncycastle.cert;

import java.io.IOException;
import java.io.OutputStream;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AttCertValidityPeriod;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.AttributeCertificateInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.util.Arrays;

public class X509AttributeCertificateHolder
{
    private AttributeCertificate attrCert;
    private X509Extensions extensions;

    public X509AttributeCertificateHolder(byte[] certEncoding)
    {
        this(AttributeCertificate.getInstance(certEncoding));
    }

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

    public boolean hasExtensions()
    {
        return extensions != null;
    }

    public X509Extension getExtension(ASN1ObjectIdentifier oid)
    {
        if (extensions != null)
        {
            return extensions.getExtension(oid);
        }

        return null;
    }

    public List getExtensionOIDs()
    {
        return CertUtils.getExtensionOIDs(extensions);
    }

    public Set getCriticalExtensionOIDs()
    {
        return CertUtils.getCriticalExtensionOIDs(extensions);
    }

    public Set getNonCriticalExtensionOIDs()
    {
        return CertUtils.getNonCriticalExtensionOIDs(extensions);
    }

    public AttributeCertificate toASN1Structure()
    {
        return attrCert;
    }

    public boolean isValidOn(Date date)
    {
        AttCertValidityPeriod certValidityPeriod = attrCert.getAcinfo().getAttrCertValidityPeriod();

        try
        {
            return !date.before(certValidityPeriod.getNotBeforeTime().getDate()) && !date.after(certValidityPeriod.getNotAfterTime().getDate());
        }
        catch (ParseException e)
        {
            throw new IllegalStateException("unable to parse dates in attribute certificate");
        }
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
