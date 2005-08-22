package org.bouncycastle.sasn1;

import java.io.IOException;

public interface Asn1Set 
{
    Asn1Object readObject() 
        throws IOException;
}
