package org.bouncycastle.cms.bc;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.operator.AsymmetricKeyWrapper;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.bc.BcAsymmetricKeyWrapper;

public abstract class BcKeyTransRecipientInfoGenerator
    implements RecipientInfoGenerator
{
    private byte[] subjectKeyIdentifier;
    private IssuerAndSerialNumber issuerSerial;
    private BcAsymmetricKeyWrapper wrapper;

    public BcKeyTransRecipientInfoGenerator(X509CertificateHolder recipientCert, BcAsymmetricKeyWrapper wrapper)
    {
        this.wrapper = wrapper;
        this.issuerSerial = recipientCert.getIssuerAndSerialNumber();
    }

    public BcKeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, BcAsymmetricKeyWrapper wrapper)
    {
        this.wrapper = wrapper;
        this.subjectKeyIdentifier = subjectKeyIdentifier;
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