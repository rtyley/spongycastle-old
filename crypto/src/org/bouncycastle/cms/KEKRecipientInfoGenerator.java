package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.KEKIdentifier;
import org.bouncycastle.asn1.cms.KEKRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public abstract class KEKRecipientInfoGenerator
    implements RecipientInfoGenerator
{
    private final KEKIdentifier kekIdentifier;
    private final AlgorithmIdentifier keyEncryptionAlgorithm;

    protected KEKRecipientInfoGenerator(KEKIdentifier kekIdentifier, AlgorithmIdentifier keyEncryptionAlgorithm)
    {
        this.kekIdentifier = kekIdentifier;
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
    }

    public final RecipientInfo generate(byte[] contentEncryptionKey)
        throws CMSException
    {
        ASN1OctetString encryptedKey = new DEROctetString(generateEncryptedBytes(keyEncryptionAlgorithm, contentEncryptionKey));

        return new RecipientInfo(new KEKRecipientInfo(kekIdentifier, keyEncryptionAlgorithm, encryptedKey));
    }

    protected abstract byte[] generateEncryptedBytes(AlgorithmIdentifier keyEncryptionAlgorithm, byte[] contentEncryptionKey)
        throws CMSException;
}