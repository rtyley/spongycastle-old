package org.bouncycastle.cms.jcajce;

import java.security.cert.X509CertSelector;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.SignerId;

public class JcaSelectorConverter
{
    public JcaSelectorConverter()
    {

    }

    public SignerId getSignerId(X509CertSelector certSelector)
    {
        if (certSelector.getSubjectKeyIdentifier() != null)
        {
            return new JcaSignerId(certSelector.getIssuer(), certSelector.getSerialNumber(), ASN1OctetString.getInstance(certSelector.getSubjectKeyIdentifier()).getOctets());
        }
        else
        {
            return new JcaSignerId(certSelector.getIssuer(), certSelector.getSerialNumber());
        }
    }

    public KeyTransRecipientId getKeyTransRecipientId(X509CertSelector certSelector)
    {
        if (certSelector.getSubjectKeyIdentifier() != null)
        {
            return new JceKeyTransRecipientId(certSelector.getIssuer(), certSelector.getSerialNumber(), ASN1OctetString.getInstance(certSelector.getSubjectKeyIdentifier()).getOctets());
        }
        else
        {
            return new JceKeyTransRecipientId(certSelector.getIssuer(), certSelector.getSerialNumber());
        }
    }
}
