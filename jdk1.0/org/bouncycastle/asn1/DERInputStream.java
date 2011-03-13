package org.spongycastle.asn1;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

public class DERInputStream
    extends FilterInputStream implements DERTags
{
    public DERInputStream(
        InputStream is)
    {
        super(is);
    }

    protected int readLength()
        throws IOException
    {
        int length = read();
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

            length = 0;
            for (int i = 0; i < size; i++)
            {
                int next = read();

                if (next < 0)
                {
                    throw new IOException("EOF found reading length");
                }

                length = (length << 8) + next;
            }
        }

        return length;
    }

    protected void readFully(
        byte[]  bytes)
        throws IOException
    {
        int     left = bytes.length;

        if (left == 0)
        {
            return;
        }

        while ((left -= read(bytes, bytes.length - left, left)) != 0)
        {
            // do nothing
        }
    }

    /**
     * build an object given its tag and a byte stream to construct it
     * from.
     */
    protected DERObject buildObject(
        int    tag,
        byte[]    bytes)
        throws IOException
    {
        switch (tag)
        {
        case NULL:
            return null;   
        case SEQUENCE | CONSTRUCTED:
            ByteArrayInputStream    bIn = new ByteArrayInputStream(bytes);
            BERInputStream          dIn = new BERInputStream(bIn);
            DERConstructedSequence  seq = new DERConstructedSequence();

            try
            {
                for (;;)
                {
                    DERObject   obj = dIn.readObject();

                    seq.addObject(obj);
                }
            }
            catch (EOFException ex)
            {
                return seq;
            }
        case SET | CONSTRUCTED:
            bIn = new ByteArrayInputStream(bytes);
            dIn = new BERInputStream(bIn);

            DERSet       set = new DERSet(dIn.readObject());

            try
            {
                for (;;)
                {
                    DERObject   obj = dIn.readObject();

                    set.addObject(obj);
                }
            }
            catch (EOFException ex)
            {
                return set;
            }
        case BOOLEAN:
            return new DERBoolean(bytes);
        case INTEGER:
            return new DERInteger(bytes);
        case OBJECT_IDENTIFIER:
            int             head = bytes[0] & 0xff;
            StringBuffer    objId = new StringBuffer();
    
            objId.append(head / 40);
            objId.append('.');
            objId.append(head % 40);
            
            int value = 0;
    
            for (int i = 1; i != bytes.length; i++)
            {
                int b = bytes[i] & 0xff;
    
                value = value * 128 + (b & 0x7f);
                if ((b & 128) == 0)             // end of number reached
                {
                    objId.append('.');
                    objId.append(value);
                    value = 0;
                }
            }
    
            return new DERObjectIdentifier(objId.toString());
        case BIT_STRING:
            int     padBits = bytes[0];
            byte[]  data = new byte[bytes.length - 1];

            System.arraycopy(bytes, 1, data, 0, bytes.length - 1);

            return new DERBitString(data, padBits);
        case PRINTABLE_STRING:
            return new DERPrintableString(bytes);
        case IA5_STRING:
            return new DERIA5String(bytes);
        case T61_STRING:
            return new DERT61String(bytes);
        case VISIBLE_STRING:
            return new DERVisibleString(bytes);
        case BMP_STRING:
            return new DERBMPString(bytes);
        case OCTET_STRING:
            return new DEROctetString(bytes);
        case GENERALIZED_TIME:
            return new DERGeneralizedTime(new String(bytes, 0));
        case UTC_TIME:
            return new DERUTCTime(new String(bytes, 0));
        default:
            //
            // with tagged object tag number is bottom 4 bits
            //
            if ((tag & (TAGGED | CONSTRUCTED)) != 0)  
            {
                if (bytes.length == 0)        // empty tag!
                {
                    return new DERTaggedObject(tag & 0x0f);
                }

                //
                // simple type - implicit... return an octet string
                //
                if ((tag & CONSTRUCTED) == 0)
                {
                    return new DERTaggedObject(false, tag & 0x0f, new DEROctetString(bytes));
                }

                bIn = new ByteArrayInputStream(bytes);
                dIn = new BERInputStream(bIn);

                DEREncodable dObj = dIn.readObject();

                //
                // explicitly tagged (probably!) - if it isn't we'd have to
                // tell from the context
                //
                if (dIn.available() == 0)
                {
                    return new DERTaggedObject(tag & 0x0f, dObj);
                }

                //
                // another implicit object, we'll create a sequence...
                //
                seq = new DERConstructedSequence();

                seq.addObject(dObj);

                try
                {
                    for (;;)
                    {
                        dObj = dIn.readObject();

                        seq.addObject(dObj);
                    }
                }
                catch (EOFException ex)
                {
                    // ignore --
                }

                return new DERTaggedObject(false, tag & 0x0f, seq);
            }

            return new DERUnknownTag(tag, bytes);
        }
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
        byte[]  bytes = new byte[length];

        readFully(bytes);

        return buildObject(tag, bytes);
    }
}
