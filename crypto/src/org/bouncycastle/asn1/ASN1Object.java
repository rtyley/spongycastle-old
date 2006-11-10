package org.bouncycastle.asn1;

import java.io.IOException;

public abstract  class ASN1Object
    extends DERObject
{
    public final boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        
        return (o instanceof DEREncodable) && asn1Equals(((DEREncodable)o).getDERObject());
    }

    public abstract int hashCode();

    abstract void encode(DEROutputStream out) throws IOException;

    abstract boolean asn1Equals(DERObject o);
}
