package org.bouncycastle.asn1;

import java.io.IOException;

public class DERBoolean
    extends ASN1Primitive
{
    byte         value;

    public static final ASN1Boolean FALSE = new ASN1Boolean(false);
    public static final ASN1Boolean TRUE  = new ASN1Boolean(true);

    /**
     * return a boolean from the passed in object.
     *
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static ASN1Boolean getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof ASN1Boolean)
        {
            return (ASN1Boolean)obj;
        }

        if (obj instanceof DERBoolean)
        {
            return ((DERBoolean)obj).isTrue() ? DERBoolean.TRUE : DERBoolean.FALSE;
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return a DERBoolean from the passed in boolean.
     */
    public static ASN1Boolean getInstance(
        boolean  value)
    {
        return (value ? TRUE : FALSE);
    }

    /**
     * return a Boolean from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     */
    public static DERBoolean getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERBoolean)
        {
            return getInstance(o);
        }
        else
        {
            return new ASN1Boolean(((ASN1OctetString)o).getOctets());
        }
    }
    
    public DERBoolean(
        byte[]       value)
    {
        if (value.length != 1)
        {
            throw new IllegalArgumentException("byte value should have 1 byte in it");
        }
        
        this.value = value[0];
    }

    public DERBoolean(
        boolean     value)
    {
        this.value = (value) ? (byte)0xff : (byte)0;
    }

    public boolean isTrue()
    {
        return (value != 0);
    }

    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        byte[]  bytes = new byte[1];

        bytes[0] = value;

        out.writeEncoded(BERTags.BOOLEAN, bytes);
    }
    
    protected boolean asn1Equals(
        ASN1Primitive  o)
    {
        if ((o == null) || !(o instanceof DERBoolean))
        {
            return false;
        }

        return (value == ((DERBoolean)o).value);
    }
    
    public int hashCode()
    {
        return value;
    }


    public String toString()
    {
      return (value != 0) ? "TRUE" : "FALSE";
    }
}
