package org.spongycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Vector;

class eos extends DERObject
{
    void encode(
        DEROutputStream out)
    throws IOException
    {
        throw new IOException("Eeek!");
    }
    
    public boolean equals(Object o)
    {
        return (o instanceof eos);
    }
    
    public int hashCode()
    {
        return 0;
    }
}

public class BERInputStream
    extends DERInputStream
{
    private static final DERObject END_OF_STREAM = new eos();

    public BERInputStream(
        InputStream is)
    {
        super(is);
    }

    /**
     * read a string of bytes representing an indefinite length object.
     */
    private byte[] readIndefiniteLengthFully()
        throws IOException
    {
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        int                     b, b1;

        b1 = read();

        while ((b = read()) >= 0)
        {
            if (b1 == 0 && b == 0)
            {
                break;
            }

            bOut.write(b1);
            b1 = b;
        }

        return bOut.toByteArray();
    }

    private BERConstructedOctetString buildConstructedOctetString(
        DEROctetString    o1,
        DEROctetString    o2)
        throws IOException
    {
        Vector                  octs = new Vector();

        if (o1 != null)
        {
            octs.addElement(o1);
            octs.addElement(o2);
        }

        for (;;)
        {
            DERObject        o = readObject();

            if (o == END_OF_STREAM)
            {
                break;
            }

            octs.addElement(o);
        }

        return new BERConstructedOctetString(octs);
    }

    public DERObject readObject()
        throws IOException
    {
        int tag = read();
        if (tag == -1)
        {
            throw new EOFException();
        }
    
        int     length = readLength();

        if (length < 0)    // indefinite length method
        {
            byte[]  bytes;
    
            switch (tag)
            {
            case NULL:
                return null;
            case SEQUENCE | CONSTRUCTED:
                BERConstructedSequence  seq = new BERConstructedSequence();
    
                for (;;)
                {
                    DERObject   obj = readObject();

                    if (obj == END_OF_STREAM)
                    {
                        break;
                    }

                    seq.addObject(obj);
                }
                return seq;
            case OCTET_STRING | CONSTRUCTED:
                return buildConstructedOctetString(null, null);
            default:
                if ((tag & (TAGGED | CONSTRUCTED)) != 0)  
                {
                    // with tagged object tag number is bottom 4 bits
                    BERTaggedObject tagObj = new BERTaggedObject(tag & 0x0f, readObject());
                    DERObject        o = readObject();

                    if (o == END_OF_STREAM)
                    {
                        return tagObj;
                    }
                    else if (o instanceof DEROctetString
                            && tagObj.getObject() instanceof DEROctetString)
                    {
                        //
                        // it's an implicit object - mark it as so...
                        //
                        tagObj = new BERTaggedObject(false, tag & 0x0f, 
                                        buildConstructedOctetString((DEROctetString)tagObj.getObject(), (DEROctetString)o));

                        return tagObj;
                    }

                    throw new IOException("truncated tagged object");
                }
    
                bytes = readIndefiniteLengthFully();

                return buildObject(tag, bytes);
            }
        }
        else
        {
            if (tag == 0 && length == 0)    // end of contents marker.
            {
                return END_OF_STREAM;
            }

            byte[]  bytes = new byte[length];
    
            readFully(bytes);
    
            return buildObject(tag, bytes);
        }
    }
}
