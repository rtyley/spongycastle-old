package org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class DERObjectIdentifier
    extends DERObject
{
    String      identifier;

    /**
     * return an OID from the passed in object
     *
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static DERObjectIdentifier getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof DERObjectIdentifier)
        {
            return (DERObjectIdentifier)obj;
        }

        if (obj instanceof ASN1OctetString)
        {
            return new DERObjectIdentifier(((ASN1OctetString)obj).getOctets());
        }

        if (obj instanceof ASN1TaggedObject)
        {
            return getInstance(((ASN1TaggedObject)obj).getObject());
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return an Object Identifier from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     */
    public static DERObjectIdentifier getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(obj.getObject());
    }
    

    DERObjectIdentifier(
        byte[]  bytes)
    {
        StringBuffer    objId = new StringBuffer();
        long            value = 0;
        boolean         first = true;

        for (int i = 0; i != bytes.length; i++)
        {
            int b = bytes[i] & 0xff;

            value = value * 128 + (b & 0x7f);
            if ((b & 0x80) == 0)             // end of number reached
            {
                if (first)
                {
                    switch ((int)value / 40)
                    {
                    case 0:
                        objId.append('0');
                        break;
                    case 1:
                        objId.append('1');
                        value -= 40;
                        break;
                    default:
                        objId.append('2');
                        value -= 80;
                    }
                    first = false;
                }

                objId.append('.');
                objId.append(Long.toString(value));
                value = 0;
            }
        }

        this.identifier = objId.toString();
    }

    public DERObjectIdentifier(
        String  identifier)
    {
        for (int i = identifier.length() - 1; i >= 0; i--)
        {
            char ch = identifier.charAt(i);
            
            if ('0' <= ch && ch <= '9')
            {
                continue;
            }
            
            if (ch == '.')
            {
                continue;
            }
            
            throw new IllegalArgumentException("string " + identifier + " not an OID");
        }
        
        this.identifier = identifier;
    }

    public String getId()
    {
        return identifier;
    }

    private void writeField(
        OutputStream    out,
        long            fieldValue)
        throws IOException
    {
        if (fieldValue >= (1L << 7))
        {
            if (fieldValue >= (1L << 14))
            {
                if (fieldValue >= (1L << 21))
                {
                    if (fieldValue >= (1L << 28))
                    {
                        if (fieldValue >= (1L << 35))
                        {
                            if (fieldValue >= (1L << 42))
                            {
                                if (fieldValue >= (1L << 49))
                                {
                                    if (fieldValue >= (1L << 56))
                                    {
                                        out.write((int)(fieldValue >> 56) | 0x80);
                                    }
                                    out.write((int)(fieldValue >> 49) | 0x80);
                                }
                                out.write((int)(fieldValue >> 42) | 0x80);
                            }
                            out.write((int)(fieldValue >> 35) | 0x80);
                        }
                        out.write((int)(fieldValue >> 28) | 0x80);
                    }
                    out.write((int)(fieldValue >> 21) | 0x80);
                }
                out.write((int)(fieldValue >> 14) | 0x80);
            }
            out.write((int)(fieldValue >> 7) | 0x80);
        }
        out.write((int)fieldValue & 0x7f);
    }

    void encode(
        DEROutputStream out)
        throws IOException
    {
        OIDTokenizer            tok = new OIDTokenizer(identifier);
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        DEROutputStream         dOut = new DEROutputStream(bOut);

        writeField(bOut, 
                    Integer.parseInt(tok.nextToken()) * 40
                    + Integer.parseInt(tok.nextToken()));

        while (tok.hasMoreTokens())
        {
            writeField(bOut, Long.parseLong(tok.nextToken()));
        }

        dOut.close();

        byte[]  bytes = bOut.toByteArray();

        out.writeEncoded(OBJECT_IDENTIFIER, bytes);
    }

    public int hashCode()
    {
        return identifier.hashCode();
    }

    public boolean equals(
        Object  o)
    {
        if ((o == null) || !(o instanceof DERObjectIdentifier))
        {
            return false;
        }

        return identifier.equals(((DERObjectIdentifier)o).identifier);
    }

    public String toString()
    {
        return getId();
    }
}
