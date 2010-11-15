package org.bouncycastle.cms.jcajce;

import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.operator.AsymmetricKeyWrapper;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;

public class JceKeyTransRecipientInfoGenerator
    implements RecipientInfoGenerator
{
    private byte[] subjectKeyIdentifier;
    private IssuerAndSerialNumber issuerSerial;
    private JceAsymmetricKeyWrapper wrapper;

    public JceKeyTransRecipientInfoGenerator(X509Certificate recipientCert)
        throws CertificateEncodingException
    {
        this.wrapper = new JceAsymmetricKeyWrapper(recipientCert.getPublicKey());
        this.issuerSerial = new JcaX509CertificateHolder(recipientCert).getIssuerAndSerialNumber();
    }

    public JceKeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, PublicKey publicKey)
    {
        this.wrapper = new JceAsymmetricKeyWrapper(publicKey);
        this.subjectKeyIdentifier = subjectKeyIdentifier;
    }

    public JceKeyTransRecipientInfoGenerator setProvider(String providerName)
        throws OperatorCreationException
    {
        this.wrapper.setProvider(providerName);

        return this;
    }

    public JceKeyTransRecipientInfoGenerator setProvider(Provider provider)
        throws OperatorCreationException
    {
        this.wrapper.setProvider(provider);

        return this;
    }

    public RecipientInfo generate(GenericKey contentEncryptionKey)
        throws CMSException
    {
        if (issuerSerial != null)
        {
            return new BaseGenerator(issuerSerial, wrapper).generate(contentEncryptionKey);
        }
        else
        {
            return new BaseGenerator(subjectKeyIdentifier, wrapper).generate(contentEncryptionKey);
        }
    }

    private class BaseGenerator
        extends KeyTransRecipientInfoGenerator
    {
        protected BaseGenerator(IssuerAndSerialNumber issuerAndSerial, AsymmetricKeyWrapper wrapper)
        {
            super(issuerAndSerial, wrapper);
        }

        protected BaseGenerator(byte[] subjectKeyIdentifier, AsymmetricKeyWrapper wrapper)
        {
            super(subjectKeyIdentifier, wrapper);
        }
    }
}