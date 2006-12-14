package org.bouncycastle.sasn1;

import java.io.IOException;
import java.io.InputStream;

/**
 * @deprecated use corresponsding classes in org.bouncycastle.asn1.
 */
public class BerSequence
    extends Asn1Object
    implements Asn1Sequence
{
    private Asn1InputStream _aIn;

    protected BerSequence(
        int         baseTag, 
        InputStream contentStream)
    {
        super(baseTag, BerTag.SEQUENCE, contentStream);

        this._aIn = new Asn1InputStream(contentStream);
    }

    public Asn1Object readObject() 
        throws IOException
    {
        return _aIn.readObject();
    }
}
