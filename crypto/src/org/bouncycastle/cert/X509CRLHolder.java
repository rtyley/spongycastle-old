package org.bouncycastle.cert;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.util.Arrays;

public class X509CRLHolder
{
    private CertificateList x509CRL;

    public X509CRLHolder(byte[] crlEncoding)
    {
        this.x509CRL = CertificateList.getInstance(crlEncoding);
    }

    public X509CRLHolder(CertificateList x509CRL)
    {
        this.x509CRL = x509CRL;
    }

    public byte[] getEncoded()
        throws IOException
    {
        return x509CRL.getEncoded();
    }

    public CertificateList toASN1Structure()
    {
        return x509CRL;
    }

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
