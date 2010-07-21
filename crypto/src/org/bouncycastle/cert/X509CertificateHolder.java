package org.bouncycastle.cert;

import java.io.IOException;

import org.bouncycastle.asn1.x509.X509CertificateStructure;

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

    public X509CertificateStructure getASN1Structure()
    {
        return x509Certificate;
    }
}
