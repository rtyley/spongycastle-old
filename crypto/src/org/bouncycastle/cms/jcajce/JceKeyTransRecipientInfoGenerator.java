package org.bouncycastle.cms.jcajce;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.KeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.AsymmetricKeyWrapper;

public class JceKeyTransRecipientInfoGenerator
    extends KeyTransRecipientInfoGenerator
{
    public JceKeyTransRecipientInfoGenerator(X509Certificate recipientCert, AsymmetricKeyWrapper wrapper)
        throws CertificateEncodingException
    {
        super(new JcaX509CertificateHolder(recipientCert).getIssuerAndSerialNumber(), wrapper);
    }
}