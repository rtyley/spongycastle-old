package org.bouncycastle.cms;

import org.bouncycastle.asn1.cms.RecipientInfo;

public interface RecipientInfoGenerator
{
    RecipientInfo generate(byte[] contentEncryptionKey)
        throws CMSException;
}
