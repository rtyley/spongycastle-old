package org.bouncycastle.sasn1;

import java.io.IOException;

/**
 * @deprecated use corresponsding classes in org.bouncycastle.asn1.
 */
public class DerSequence
    extends DerObject
    implements Asn1Sequence
{    
    private Asn1InputStream _aIn;

    DerSequence(
        int baseTag,
        byte[] content)
    {
        super(baseTag, BerTag.SEQUENCE, content);
        
        this._aIn = new Asn1InputStream(content);
    }

    public Asn1Object readObject() 
        throws IOException
    {
        return _aIn.readObject();
    }
}
