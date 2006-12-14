package org.bouncycastle.sasn1;

import java.io.InputStream;

/**
 * @deprecated use corresponsding classes in org.bouncycastle.asn1.
 */
public class BerOctetString
    extends Asn1Object
    implements Asn1OctetString
{   
    protected BerOctetString(
        int         baseTag,
        InputStream contentStream)
    {
        super(baseTag, BerTag.OCTET_STRING, contentStream);
    }
    
    public InputStream getOctetStream()
    {
        if (this.isConstructed())
        {
            return new ConstructedOctetStream(this.getRawContentStream());
        }
        else
        {
            return this.getRawContentStream();
        }
    }
}
