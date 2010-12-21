package org.bouncycastle.cms.bc;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.KeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.bc.BcAsymmetricKeyWrapper;

public abstract class BcKeyTransRecipientInfoGenerator
    extends KeyTransRecipientInfoGenerator
{
    public BcKeyTransRecipientInfoGenerator(X509CertificateHolder recipientCert, BcAsymmetricKeyWrapper wrapper)
    {
        super(recipientCert.getIssuerAndSerialNumber(), wrapper);
    }

    public BcKeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, BcAsymmetricKeyWrapper wrapper)
    {
        super(subjectKeyIdentifier, wrapper);
    }
}