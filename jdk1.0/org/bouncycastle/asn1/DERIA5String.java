package org.spongycastle.asn1;

import java.io.IOException;

/**
 * DER IA5String object - this is an ascii string, strictly speaking
 * we don't handle this correctly as we're taking advantage of the fact the
 * default platform encoding is ascii... later!
 */
public class DERIA5String
    extends DERObject
{
    String  string;

    /**
     * return a IA5 string from the passed in object
     *
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static DERIA5String getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof DERIA5String)
        {
            return (DERIA5String)obj;
        }

        if (obj instanceof ASN1OctetString)
        {
            return new DERIA5String(((ASN1OctetString)obj).getOctets());
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return an IA5 String from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     */
    public static DERIA5String getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(obj.getObject());
    }

    public DERIA5String(
        String   string)
    {
        this.string = string;
    }

    /**
     * @param string - bytes representing the string.
     */
    public DERIA5String(
        byte[]   string)
    {
        this.string = new String(string, 0);
    }

    public String getString()
    {
        return string;
    }

    void encode(
        DEROutputStream  out)
        throws IOException
    {
        byte[]  bytes = new byte[string.length()];

        string.getBytes(0, string.length(), bytes, 0);

        out.writeEncoded(IA5_STRING, bytes);
    }
    
    public int hashCode()
    {
        return this.getString().hashCode();
    }

    public boolean equals(
        Object  o)
    {
        if (!(o instanceof DERIA5String))
        {
            return false;
        }

        DERIA5String  s = (DERIA5String)o;

        return this.getString().equals(s.getString());
    }
}
