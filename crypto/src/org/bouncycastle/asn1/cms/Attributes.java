package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObject;

public class Attributes
    extends ASN1Encodable
{
    private ASN1Set attributes;

    private Attributes(ASN1Set set)
    {
        attributes = set;
    }

    public static Attributes getInstance(Object obj)
    {
        if (obj instanceof Attributes)
        {
            return (Attributes)obj;
        }
        else if (obj != null)
        {
            return new Attributes(ASN1Set.getInstance(obj));
        }

        throw new IllegalArgumentException("null object in factory");
    }

    /**
     * <pre>
     * Attributes ::=
     *   SET SIZE(1..MAX) OF Attribute -- according to RFC 5652
     * </pre>
     * @return
     */
    public DERObject toASN1Object()
    {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }
}
