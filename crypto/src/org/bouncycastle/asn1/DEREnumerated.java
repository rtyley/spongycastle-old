package org.bouncycastle.asn1;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.util.Arrays;

public class DEREnumerated
    extends ASN1Primitive
{
    byte[]      bytes;

    /**
     * return an integer from the passed in object
     *
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static ASN1Enumerated getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof ASN1Enumerated)
        {
            return (ASN1Enumerated)obj;
        }

        if (obj instanceof DEREnumerated)
        {
            return new ASN1Enumerated(((DEREnumerated)obj).getValue());
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return an Enumerated from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     */
    public static DEREnumerated getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DEREnumerated)
        {
            return getInstance(o);
        }
        else
        {
            return new ASN1Enumerated(((ASN1OctetString)o).getOctets());
        }
    }

    public DEREnumerated(
        int         value)
    {
        bytes = BigInteger.valueOf(value).toByteArray();
    }

    public DEREnumerated(
        BigInteger   value)
    {
        bytes = value.toByteArray();
    }

    public DEREnumerated(
        byte[]   bytes)
    {
        this.bytes = bytes;
    }

    public BigInteger getValue()
    {
        return new BigInteger(bytes);
    }

    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        out.writeEncoded(BERTags.ENUMERATED, bytes);
    }
    
    boolean asn1Equals(
        ASN1Primitive  o)
    {
        if (!(o instanceof DEREnumerated))
        {
            return false;
        }

        DEREnumerated other = (DEREnumerated)o;

        return Arrays.areEqual(this.bytes, other.bytes);
    }

    public int hashCode()
    {
        return Arrays.hashCode(bytes);
    }
}
