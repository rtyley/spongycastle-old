package org.bouncycastle.cert.selector.jcajce;

import java.security.cert.X509CertSelector;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.cert.selector.X509CertificateHolderSelector;

public class JcaSelectorConverter
{
    public JcaSelectorConverter()
    {

    }

    public X509CertificateHolderSelector getCertificateHolderSelector(X509CertSelector certSelector)
    {
        if (certSelector.getSubjectKeyIdentifier() != null)
        {
            return new JcaX509CertificateHolderSelector(certSelector.getIssuer(), certSelector.getSerialNumber(), ASN1OctetString.getInstance(certSelector.getSubjectKeyIdentifier()).getOctets());
        }
        else
        {
            return new JcaX509CertificateHolderSelector(certSelector.getIssuer(), certSelector.getSerialNumber());
        }
    }
}
