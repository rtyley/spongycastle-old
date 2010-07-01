package org.bouncycastle.asn1.crmf;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.GeneralName;

public class EncKeyWithID
    extends ASN1Encodable
{
    private final PrivateKeyInfo privKeyInfo;
    private final ASN1Encodable identifier;

    public EncKeyWithID(PrivateKeyInfo privKeyInfo)
    {
        this.privKeyInfo = privKeyInfo;
        this.identifier = null;
    }

    public EncKeyWithID(PrivateKeyInfo privKeyInfo, DERUTF8String str)
    {
        this.privKeyInfo = privKeyInfo;
        this.identifier = str;
    }

    public EncKeyWithID(PrivateKeyInfo privKeyInfo, GeneralName generalName)
    {
        this.privKeyInfo = privKeyInfo;
        this.identifier = generalName;
    }

    /**
     * <pre>
     * EncKeyWithID ::= SEQUENCE {
     *      privateKey           PrivateKeyInfo,
     *      identifier CHOICE {
     *         string               UTF8String,
     *         generalName          GeneralName
     *     } OPTIONAL
     * }
     * </pre>
     * @return
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(privKeyInfo);

        if (identifier != null)
        {
            v.add(identifier);
        }

        return new DERSequence(v);
    }
}
