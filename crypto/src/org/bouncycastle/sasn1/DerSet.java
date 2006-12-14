package org.bouncycastle.sasn1;

import java.io.IOException;

/**
 * @deprecated use corresponsding classes in org.bouncycastle.asn1.
 */
public class DerSet
    extends DerObject
    implements Asn1Set
{    
    private Asn1InputStream _aIn;

    DerSet(
        int baseTag,
        byte[] content)
    {
        super(baseTag, BerTag.SET, content);
        
        this._aIn = new Asn1InputStream(content);
    }

    public Asn1Object readObject() 
        throws IOException
    {
        return _aIn.readObject();
    }
}
