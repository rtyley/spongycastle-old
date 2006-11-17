package org.bouncycastle.asn1;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

public class ASN1StreamParser
{
    InputStream _in;

    private int     _limit;
    private boolean _eofFound;

    public ASN1StreamParser(
        InputStream in)
    {
        this(in, Integer.MAX_VALUE);
    }

    public ASN1StreamParser(
        InputStream in,
        int         limit)
    {
        this._in = in;
        this._limit = limit;
    }

    public ASN1StreamParser(
        byte[] encoding)
    {
        this(new ByteArrayInputStream(encoding), encoding.length);
    }

    InputStream getParentStream()
    {
        return _in;
    }

    private int readLength()
        throws IOException
    {
        int length = _in.read();
        if (length < 0)
        {
            throw new EOFException("EOF found when length expected");
        }

        if (length == 0x80)
        {
            return -1;      // indefinite-length encoding
        }

        if (length > 127)
        {
            int size = length & 0x7f;

            if (size > 4)
            {
                throw new IOException("DER length more than 4 bytes");
            }

            length = 0;
            for (int i = 0; i < size; i++)
            {
                int next = _in.read();

                if (next < 0)
                {
                    throw new EOFException("EOF found reading length");
                }

                length = (length << 8) + next;
            }

            if (length < 0)
            {
                throw new IOException("corrupted steam - negative length found");
            }

            if (length >= _limit)   // after all we must have read at least 1 byte
            {
                throw new IOException("corrupted steam - out of bounds length found");
            }
        }

        return length;
    }

    public DEREncodable readObject()
        throws IOException
    {
        int tag = _in.read();
        if (tag == -1)
        {
            if (_eofFound)
            {
                throw new EOFException("attempt to read past end of file.");
            }

            _eofFound = true;

            return null;
        }

        //
        // turn of looking for "00" while we resolve the tag
        //
        if (_in instanceof IndefiniteLengthInputStream)
        {
            ((IndefiniteLengthInputStream)_in).setEofOn00(false);
        }

        //
        // calculate tag number
        //
        int baseTagNo = tag & ~DERTags.CONSTRUCTED;
        int tagNo = baseTagNo;

        if ((tag & DERTags.TAGGED) != 0)
        {
            tagNo = tag & 0x1f;

            //
            // with tagged object tag number is bottom 5 bits, or stored at the start of the content
            //
            if (tagNo == 0x1f)
            {
                tagNo = 0;

                int b = _in.read();

                while ((b >= 0) && ((b & 0x80) != 0))
                {
                    tagNo |= (b & 0x7f);
                    tagNo <<= 7;
                    b = _in.read();
                }

                if (b < 0)
                {
                    _eofFound = true;

                    throw new EOFException("EOF encountered inside tag value.");
                }

                tagNo |= (b & 0x7f);
            }
        }

        //
        // calculate length
        //
        int length = readLength();

        if (length < 0)  // indefinite length
        {
            IndefiniteLengthInputStream indIn = new IndefiniteLengthInputStream(_in);

            if (baseTagNo == DERTags.NULL)
            {
                return BERNull.INSTANCE;
            }

            switch (baseTagNo)
            {
            case DERTags.OCTET_STRING:
                return new BEROctetStringParser(new ASN1ObjectParser(tag, tagNo, indIn));
            case DERTags.SEQUENCE:
                return new BERSequenceParser(new ASN1ObjectParser(tag, tagNo, indIn));
            case DERTags.SET:
                return new BERSetParser(new ASN1ObjectParser(tag, tagNo, indIn));
            default:
                return new BERTaggedObjectParser(tag, tagNo, indIn);
            }
        }
        else
        {
            DefiniteLengthInputStream defIn = new DefiniteLengthInputStream(_in, length);

            switch (baseTagNo)
            {
            case DERTags.INTEGER:
                return new DERInteger(defIn.toByteArray());
            case DERTags.NULL:
                return DERNull.INSTANCE;
            case DERTags.OBJECT_IDENTIFIER:
                return new DERObjectIdentifier(defIn.toByteArray());
            case DERTags.OCTET_STRING:
                return new DEROctetString(defIn.toByteArray());
            case DERTags.SEQUENCE:
                return new DERSequence(loadVector(defIn.toByteArray())).parser();
            case DERTags.SET:
                return new DERSet(loadVector(defIn.toByteArray())).parser();
            default:
                return new BERTaggedObjectParser(tag, tagNo, defIn);
            }
        }
    }

    private ASN1EncodableVector loadVector(byte[] bytes)
        throws IOException
    {
        ASN1InputStream         aIn = new ASN1InputStream(bytes);
        ASN1EncodableVector     v = new ASN1EncodableVector();

        DERObject   obj = aIn.readObject();

        while (obj != null)
        {
            v.add(obj);
            obj = aIn.readObject();
        }

        return v;
    }
}
