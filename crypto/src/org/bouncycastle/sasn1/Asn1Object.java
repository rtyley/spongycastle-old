package org.bouncycastle.sasn1;

import java.io.InputStream;

/**
 * @deprecated use corresponsding classes in org.bouncycastle.asn1.
 */
public abstract class Asn1Object
{
    protected int         _baseTag;
    protected int         _tagNumber;
    protected InputStream _contentStream;
    
    protected Asn1Object(
        int         baseTag,
        int         tagNumber,
        InputStream contentStream)
    {
        this._baseTag = baseTag;
        this._tagNumber = tagNumber;
        this._contentStream = contentStream;
    }
    
    /**
     * Return true if this object is a constructed one.
     * 
     * @return true if this object is constructed.
     */
    public boolean isConstructed()
    {
        return (_baseTag & BerTag.CONSTRUCTED) != 0;
    }
    
    /**
     * Return the tag number for this object.
     * 
     * @return the tag number.
     */
    public int getTagNumber()
    {
        return _tagNumber;
    }

    /**
     * Return an input stream representing the content bytes of the object.
     * 
     * @return content stream.
     */
    public InputStream getRawContentStream()
    {   
        return _contentStream;
    }
}
