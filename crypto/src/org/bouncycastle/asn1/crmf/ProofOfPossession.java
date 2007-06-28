package org.bouncycastle.asn1.crmf;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERTaggedObject;

public class ProofOfPossession
    extends ASN1Encodable
    implements ASN1Choice
{
    private int tagNo;
    private ASN1Encodable obj;

    private ProofOfPossession(ASN1TaggedObject tagged)
    {
        tagNo = tagged.getTagNo();
    }

    public static ProofOfPossession getInstance(Object o)
    {
        if (o instanceof ProofOfPossession)
        {
            return (ProofOfPossession)o;
        }

        if (o instanceof ASN1TaggedObject)
        {
            return new ProofOfPossession((ASN1TaggedObject)o);
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    /**
     * <pre>
     * ProofOfPossession ::= CHOICE {
     *                           raVerified        [0] NULL,
     *                           -- used if the RA has already verified that the requester is in
     *                           -- possession of the private key
     *                           signature         [1] POPOSigningKey,
     *                           keyEncipherment   [2] POPOPrivKey,
     *                           keyAgreement      [3] POPOPrivKey }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public DERObject toASN1Object()
    {
        return new DERTaggedObject(tagNo, obj);
    }
}
