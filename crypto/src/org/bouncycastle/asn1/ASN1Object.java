package org.bouncycastle.asn1;

import java.io.IOException;

public abstract  class ASN1Object
    extends DERObject
{
    /**
     *
     * @param data
     * @return
     */
    public static ASN1Object fromByteArray(byte[] data)
        throws IOException
    {
        ASN1InputStream aIn = new ASN1InputStream(data);

        return (ASN1Object)aIn.readObject();
    }

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
