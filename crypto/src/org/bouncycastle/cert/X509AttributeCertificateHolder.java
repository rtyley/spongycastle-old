package org.bouncycastle.cert;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.AttributeCertificateInfo;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.util.Arrays;

public class X509AttributeCertificateHolder
{
    private AttributeCertificate attrCert;

    public X509AttributeCertificateHolder(byte[] certEncoding)
    {
        this.attrCert = AttributeCertificate.getInstance(certEncoding);
    }

    public X509AttributeCertificateHolder(AttributeCertificate attrCert)
    {
        this.attrCert = attrCert;
    }

    public byte[] getEncoded()
        throws IOException
    {
        return attrCert.getEncoded();
    }

    public AttributeCertificate toASN1Structure()
    {
        return attrCert;
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
