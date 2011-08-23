package org.bouncycastle.asn1.crmf;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.GeneralName;

public class SinglePubInfo
    extends ASN1Object
{
    private DERInteger pubMethod;
    private GeneralName pubLocation;

    private SinglePubInfo(ASN1Sequence seq)
    {
        pubMethod = DERInteger.getInstance(seq.getObjectAt(0));

        if (seq.size() == 2)
        {
            pubLocation = GeneralName.getInstance(seq.getObjectAt(1));
        }
    }

    public static SinglePubInfo getInstance(Object o)
    {
        if (o instanceof SinglePubInfo)
        {
            return (SinglePubInfo)o;
        }

        if (o instanceof ASN1Sequence)
        {
            return new SinglePubInfo((ASN1Sequence)o);
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public GeneralName getPubLocation()
    {
        return pubLocation;
    }

    /**
     * <pre>
     * SinglePubInfo ::= SEQUENCE {
     *        pubMethod    INTEGER {
     *           dontCare    (0),
     *           x500        (1),
     *           web         (2),
     *           ldap        (3) },
     *       pubLocation  GeneralName OPTIONAL }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(pubMethod);

        if (pubLocation != null)
        {
            v.add(pubLocation);
        }

        return new DERSequence(v);
    }
}
