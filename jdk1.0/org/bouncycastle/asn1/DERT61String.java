package org.spongycastle.asn1;

import java.io.IOException;

/**
 * DER T61String object.
 */
public class DERT61String
    extends DERObject
{
    String  string;

    public DERT61String(
        String   string)
    {
        this.string = string;
    }

    /**
     * @param string - bytes representing the string
     */
    public DERT61String(
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

        out.writeEncoded(T61_STRING, bytes);
    }
    
    public boolean equals(
        Object  o)
    {
        if ((o == null) || !(o instanceof DERT61String))
        {
            return false;
        }

        return this.getString().equals(((DERT61String)o).getString());
    }
    
    public int hashCode()
    {
        return this.getString().hashCode();
    }
}
