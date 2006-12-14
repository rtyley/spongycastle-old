package org.bouncycastle.sasn1;

import java.io.IOException;

/**
 * @deprecated use corresponsding classes in org.bouncycastle.asn1.
 */
public interface Asn1Set
{
    Asn1Object readObject() 
        throws IOException;
}
