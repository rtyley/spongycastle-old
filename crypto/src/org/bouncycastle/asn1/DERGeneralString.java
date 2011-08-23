package org.bouncycastle.asn1;

import java.io.IOException;

public class DERGeneralString 
    extends ASN1Primitive
    implements ASN1String
{
    private String string;

    public static DERGeneralString getInstance(
        Object obj) 
    {
        if (obj == null || obj instanceof DERGeneralString) 
        {
            return (DERGeneralString) obj;
        }

        throw new IllegalArgumentException("illegal object in getInstance: "
                + obj.getClass().getName());
    }

    public static DERGeneralString getInstance(
        ASN1TaggedObject obj, 
        boolean explicit) 
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERGeneralString)
        {
            return getInstance(o);
        }
        else
        {
            return new DERGeneralString(((ASN1OctetString)o).getOctets());
        }
    }

    public DERGeneralString(byte[] string) 
    {
        char[] cs = new char[string.length];
        for (int i = 0; i != cs.length; i++)
        {
            cs[i] = (char)(string[i] & 0xff);
        }
        this.string = new String(cs);
    }

    public DERGeneralString(String string) 
    {
        this.string = string;
    }
    
    public String getString() 
    {
        return string;
    }

    public String toString()
    {
        return string;
    }

    public byte[] getOctets() 
    {
        char[] cs = string.toCharArray();
        byte[] bs = new byte[cs.length];
        for (int i = 0; i != cs.length; i++) 
        {
            bs[i] = (byte) cs[i];
        }
        return bs;
    }
    
    void encode(ASN1OutputStream out)
        throws IOException 
    {
        out.writeEncoded(BERTags.GENERAL_STRING, this.getOctets());
    }
    
    public int hashCode() 
    {
        return this.getString().hashCode();
    }
    
    boolean asn1Equals(ASN1Primitive o)
    {
        if (!(o instanceof DERGeneralString)) 
        {
            return false;
        }
        DERGeneralString s = (DERGeneralString) o;
        return this.getString().equals(s.getString());
    }
}
