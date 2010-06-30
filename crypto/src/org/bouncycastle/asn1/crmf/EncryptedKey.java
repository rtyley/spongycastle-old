package org.bouncycastle.asn1.crmf;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.EnvelopedData;

public class EncryptedKey
    extends ASN1Encodable
    implements ASN1Choice
{
    private EnvelopedData envData;
    
    /**
     * <pre>
     *    EncryptedKey ::= CHOICE {
     *        encryptedValue        EncryptedValue, -- deprecated
     *        envelopedData     [0] EnvelopedData }
     *        -- The encrypted private key MUST be placed in the envelopedData
     *        -- encryptedContentInfo encryptedContent OCTET STRING.
     * </pre>
     */
    public DERObject toASN1Object()
    {
        return new DERTaggedObject(false, 0, envData);
    }
}
