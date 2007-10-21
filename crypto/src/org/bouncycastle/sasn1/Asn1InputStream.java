package org.bouncycastle.sasn1;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

/**
 * @deprecated use org.bouncycastle.asn1.ASN1StreamParser
 */
public class Asn1InputStream
{
    InputStream     _in;
    private int     _limit;
    private boolean _eofFound;
    
    public Asn1InputStream(
        InputStream in)
    {
        this._in = in;
        this._limit = Integer.MAX_VALUE;
    }
    
    public Asn1InputStream(
        InputStream in,
        int         limit)
    {
        this._in = in;
        this._limit = limit;
    }
                
    public Asn1InputStream(
        byte[] encoding)
    {
        this._in = new ByteArrayInputStream(encoding);
        this._limit = encoding.length;
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
            throw new IOException("EOF found when length expected");
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
                    throw new IOException("EOF found reading length");
                }
    
                length = (length << 8) + next;
            }
            
            if (length < 0)
            {
                throw new IOException("corrupted stream - negative length found");
            }

            if (length >= _limit)   // after all we must have read at least 1 byte
            {
                throw new IOException("corrupted stream - out of bounds length found");
            }
        }
    
        return length;
    }
    
    public Asn1Object readObject()
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
        int baseTagNo = tag & ~BerTag.CONSTRUCTED;
        int tagNo = baseTagNo;
        
        if ((tag & BerTag.TAGGED) != 0)  
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
            
            switch (baseTagNo)
            {
            case BerTag.NULL:
                return new Asn1Null(tag);
            case BerTag.OCTET_STRING:
                return new BerOctetString(tag, indIn);
            case BerTag.SEQUENCE:
                return new BerSequence(tag, indIn);
            case BerTag.SET:
                return new BerSet(tag, indIn);
            default:
                return new Asn1TaggedObject(tag, tagNo, indIn);
            }
        }
        else
        {
            DefiniteLengthInputStream defIn = new DefiniteLengthInputStream(_in, length);

            switch (baseTagNo)
            {
            case BerTag.INTEGER:
                return new Asn1Integer(tag, defIn.toByteArray());
            case BerTag.NULL:
                return new Asn1Null(tag);
            case BerTag.OBJECT_IDENTIFIER:
                return new Asn1ObjectIdentifier(tag, defIn.toByteArray());
            case BerTag.OCTET_STRING:
                return new DerOctetString(tag, defIn.toByteArray());
            case BerTag.SEQUENCE:
                return new DerSequence(tag, defIn.toByteArray());
            case BerTag.SET:
                return new DerSet(tag, defIn.toByteArray());
            default:
                return new Asn1TaggedObject(tag, tagNo, defIn);
            }
        }
    }
}
