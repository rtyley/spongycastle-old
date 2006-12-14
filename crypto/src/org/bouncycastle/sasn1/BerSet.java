package org.bouncycastle.sasn1;

import java.io.IOException;
import java.io.InputStream;

/**
 * @deprecated use corresponsding classes in org.bouncycastle.asn1.
 */
public class BerSet
    extends Asn1Object
    implements Asn1Set
{
    private Asn1InputStream _aIn;

    protected BerSet(
        int         baseTag, 
        InputStream contentStream)
    {
        super(baseTag, BerTag.SET, contentStream);

        this._aIn = new Asn1InputStream(contentStream);
    }

    public Asn1Object readObject() 
        throws IOException
    {
        return _aIn.readObject();
    }
}
