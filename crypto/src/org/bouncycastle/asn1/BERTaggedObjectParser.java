package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.InputStream;

public class BERTaggedObjectParser
    implements ASN1TaggedObjectParser
{
    private boolean _constructed;
    private int _tagNumber;
    private InputStream _contentStream;
    private boolean _indefiniteLength;

    /**
     * @deprecated
     */
    protected BERTaggedObjectParser(
        int         baseTag,
        int         tagNumber,
        InputStream contentStream)
    {
        this((baseTag & DERTags.CONSTRUCTED) != 0, tagNumber, contentStream);
    }

    BERTaggedObjectParser(
        boolean     constructed,
        int         tagNumber,
        InputStream contentStream)
    {
        _constructed = constructed;
        _tagNumber = tagNumber;
        _contentStream = contentStream;
        _indefiniteLength = contentStream instanceof IndefiniteLengthInputStream;
    }

    public boolean isConstructed()
    {
        return _constructed;
    }

    public int getTagNo()
    {
        return _tagNumber;
    }

    public DEREncodable getObjectParser(
        int     tag,
        boolean isExplicit)
        throws IOException
    {
        if (isExplicit)
        {
            return new ASN1StreamParser(_contentStream).readObject();
        }

        return new ASN1StreamParser(_contentStream).readImplicit(_constructed, tag);
    }

    private ASN1EncodableVector rLoadVector(InputStream in)
        throws IOException
    {
        return new ASN1StreamParser(in).readVector();
    }

    public DERObject getLoadedObject()
        throws IOException
    {
        if (_indefiniteLength)
        {
            ASN1EncodableVector v = rLoadVector(_contentStream);

            return v.size() == 1
                ?   new BERTaggedObject(true, _tagNumber, v.get(0))
                :   new BERTaggedObject(false, _tagNumber, BERFactory.createSequence(v));
        }

        if (this.isConstructed())
        {
            ASN1EncodableVector v = rLoadVector(_contentStream);

            return v.size() == 1
                ?   new DERTaggedObject(true, _tagNumber, v.get(0))
                :   new DERTaggedObject(false, _tagNumber, DERFactory.createSequence(v));
        }

        DefiniteLengthInputStream defIn = (DefiniteLengthInputStream)_contentStream;
        return new DERTaggedObject(false, _tagNumber, new DEROctetString(defIn.toByteArray()));
    }

    public DERObject getDERObject()
    {
        try
        {
            return this.getLoadedObject();
        }
        catch (IOException e)
        {
            throw new ASN1ParsingException(e.getMessage());
        }
    }
}
