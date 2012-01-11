package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Strings;

/**
 * DER UTF8String object.
 */
public class DERUTF8String
    extends ASN1Primitive
    implements ASN1String
{
    private char[]  string;
    private int     bodyLength = -1;

    /**
     * return an UTF8 string from the passed in object.
     * 
     * @exception IllegalArgumentException
     *                if the object cannot be converted.
     */
    public static DERUTF8String getInstance(Object obj)
    {
        if (obj == null || obj instanceof DERUTF8String)
        {
            return (DERUTF8String)obj;
        }

        throw new IllegalArgumentException("illegal object in getInstance: "
                + obj.getClass().getName());
    }

    /**
     * return an UTF8 String from a tagged object.
     * 
     * @param obj
     *            the tagged object holding the object we want
     * @param explicit
     *            true if the object is meant to be explicitly tagged false
     *            otherwise.
     * @exception IllegalArgumentException
     *                if the tagged object cannot be converted.
     */
    public static DERUTF8String getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERUTF8String)
        {
            return getInstance(o);
        }
        else
        {
            return new DERUTF8String(ASN1OctetString.getInstance(o).getOctets());
        }
    }

    /**
     * basic constructor - byte encoded string.
     */
    public DERUTF8String(byte[] string)
    {
        try
        {
            this.string = Strings.fromUTF8ByteArray(string).toCharArray();
        }
        catch (ArrayIndexOutOfBoundsException e)
        {
            throw new IllegalArgumentException("UTF8 encoding invalid");
        }
    }

    /**
     * basic constructor
     */
    public DERUTF8String(String string)
    {
        this.string = string.toCharArray();
    }

    public String getString()
    {
        return new String(string);
    }

    public String toString()
    {
        return new String(string);
    }

    public int hashCode()
    {
        return this.getString().hashCode();
    }

    boolean asn1Equals(ASN1Primitive o)
    {
        if (!(o instanceof DERUTF8String))
        {
            return false;
        }

        DERUTF8String s = (DERUTF8String)o;

        return this.getString().equals(s.getString());
    }

    private int getBodyLength()
        throws IOException
    {
        if (bodyLength < 0)
        {
            bodyLength = Strings.toUTF8ByteArray(string).length;
        }

        return bodyLength;
    }

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength()
        throws IOException
    {
        int length = getBodyLength();

        return 1 + StreamUtil.calculateBodyLength(length) + length;
    }

    void encode(ASN1OutputStream out)
        throws IOException
    {
        int length = getBodyLength();

        out.write(BERTags.UTF8_STRING);
        out.writeLength(length);

        Strings.toUTF8ByteArray(string, out.getRawSubStream());
    }
}
