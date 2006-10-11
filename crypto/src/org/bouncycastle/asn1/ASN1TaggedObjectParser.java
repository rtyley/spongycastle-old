package org.bouncycastle.asn1;

import java.io.IOException;

public interface ASN1TaggedObjectParser
    extends DEREncodable
{
    public int getTagNo();
    
    public DEREncodable getObject(int tag, boolean isExplicit)
        throws IOException;
}
