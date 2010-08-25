package org.bouncycastle.cms.jcajce;

import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.KeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;

public class JceKeyTransRecipientInfoGenerator
    extends KeyTransRecipientInfoGenerator
{
    public JceKeyTransRecipientInfoGenerator(X509Certificate recipientCert)
        throws CertificateEncodingException
    {
        super(new JcaX509CertificateHolder(recipientCert), new JceAsymmetricKeyWrapper(recipientCert));
    }

    public JceKeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, PublicKey recipientPublicKey)
    {
        super(subjectKeyIdentifier, new JceAsymmetricKeyWrapper(recipientPublicKey));
    }

    public JceKeyTransRecipientInfoGenerator setProvider(Provider provider)
    {
        ((JceAsymmetricKeyWrapper)wrapper).setProvider(provider);

        return this;
    }

    public JceKeyTransRecipientInfoGenerator setProvider(String providerName)
    {
        ((JceAsymmetricKeyWrapper)wrapper).setProvider(providerName);

        return this;
    }

    public JceKeyTransRecipientInfoGenerator setSecureRandom(SecureRandom random)
    {
        ((JceAsymmetricKeyWrapper)wrapper).setSecureRandom(random);

        return this;
    }
}