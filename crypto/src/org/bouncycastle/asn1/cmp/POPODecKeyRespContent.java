package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;

public class POPODecKeyRespContent
    extends ASN1Object
{
    private ASN1Sequence content;

    private POPODecKeyRespContent(ASN1Sequence seq)
    {
        content = seq;
    }

    public static POPODecKeyRespContent getInstance(Object o)
    {
        if (o instanceof POPODecKeyRespContent)
        {
            return (POPODecKeyRespContent)o;
        }

        if (o instanceof ASN1Sequence)
        {
            return new POPODecKeyRespContent((ASN1Sequence)o);
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public DERInteger[] toDERIntegerArray()
    {
        DERInteger[] result = new DERInteger[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = DERInteger.getInstance(content.getObjectAt(i));
        }

        return result;
    }

    /**
     * <pre>
     * POPODecKeyRespContent ::= SEQUENCE OF INTEGER
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}
