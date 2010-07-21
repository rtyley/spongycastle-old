package org.bouncycastle.cert.jcajce;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.cert.X509CertificateHolder;

public class JcaX509CertificateHolder
    extends X509CertificateHolder
{
    public JcaX509CertificateHolder(X509Certificate cert)
        throws CertificateEncodingException
    {
        super(X509CertificateStructure.getInstance(cert.getEncoded()));
    }
}
