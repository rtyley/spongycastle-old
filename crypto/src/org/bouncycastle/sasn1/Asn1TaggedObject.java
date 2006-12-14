package org.bouncycastle.sasn1;

import java.io.IOException;
import java.io.InputStream;

/**
 * @deprecated use corresponsding classes in org.bouncycastle.asn1.
 */
public class Asn1TaggedObject
    extends Asn1Object
{
    protected Asn1TaggedObject(
        int         baseTag,
        int         tagNumber,
        InputStream contentStream)
    {
        super(baseTag, tagNumber, contentStream);
    }

    public Asn1Object getObject(
        int     tag,
        boolean isExplicit) 
        throws IOException
    {
        if (isExplicit)
        {
            return new Asn1InputStream(this.getRawContentStream()).readObject();
        }
        else
        {
            switch (tag)
            {
            case BerTag.SET:
                if (this.getRawContentStream() instanceof IndefiniteLengthInputStream)
                {
                    return new BerSet(BerTag.CONSTRUCTED, this.getRawContentStream());
                }
                else
                {
                    return new DerSet(BerTag.CONSTRUCTED, ((DefiniteLengthInputStream)this.getRawContentStream()).toByteArray());
                }
            case BerTag.SEQUENCE:
                if (this.getRawContentStream() instanceof IndefiniteLengthInputStream)
                {
                    return new BerSequence(BerTag.CONSTRUCTED, this.getRawContentStream());
                }
                else
                {
                    return new DerSequence(BerTag.CONSTRUCTED, ((DefiniteLengthInputStream)this.getRawContentStream()).toByteArray());
                }
            case BerTag.OCTET_STRING:
                if (this.getRawContentStream() instanceof IndefiniteLengthInputStream)
                {
                    return new BerOctetString(BerTag.CONSTRUCTED, this.getRawContentStream());
                }
                else
                {
                    if (this.isConstructed())
                    {
                        return new DerOctetString(BerTag.CONSTRUCTED, ((DefiniteLengthInputStream)this.getRawContentStream()).toByteArray());
                    }
                    else
                    {
                        return new DerOctetString(BerTagClass.UNIVERSAL, ((DefiniteLengthInputStream)this.getRawContentStream()).toByteArray());
                    }
                }
            }
        }
        
        throw new RuntimeException("implicit tagging not implemented");
    }
}
