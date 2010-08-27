package org.bouncycastle.cert;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.util.Arrays;

public class X509CertificateHolder
{
    private X509CertificateStructure x509Certificate;

    public X509CertificateHolder(X509CertificateStructure x509Certificate)
    {
        this.x509Certificate = x509Certificate;
    }

    public byte[] getEncoded()
        throws IOException
    {
        return x509Certificate.getEncoded();
    }

    public IssuerAndSerialNumber getIssuerAndSerialNumber()
    {
        return new IssuerAndSerialNumber(x509Certificate.getIssuer(), x509Certificate.getSerialNumber());
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo()
    {
        return x509Certificate.getSubjectPublicKeyInfo();
    }

    public X509CertificateStructure toASN1Structure()
    {
        return x509Certificate;
    }

    public boolean isSignatureValid(ContentVerifierProvider verifierProvider)
        throws CertException
    {
        TBSCertificateStructure tbsCert = x509Certificate.getTBSCertificate();

        if (!tbsCert.getSignature().equals(x509Certificate.getSignatureAlgorithm()))
        {
            throw new CertException("signature invalid - algorithm identifier mismatch");
        }

        ContentVerifier verifier;

        try
        {
            verifier = verifierProvider.get((tbsCert.getSignature()));

            OutputStream sOut = verifier.getOutputStream();

            sOut.write(tbsCert.getDEREncoded());

            sOut.close();
        }
        catch (Exception e)
        {
            throw new CertException("unable to process signature: " + e.getMessage(), e);
        }

        return verifier.verify(x509Certificate.getSignature().getBytes());
    }

    public boolean equals(
        Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof X509CertificateHolder))
        {
            return false;
        }

        X509CertificateHolder other = (X509CertificateHolder)o;

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
