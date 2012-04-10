package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * DER Visible String object.
 */
public class DERVisibleString
    extends DERObject
{
    String  string;

    public DERVisibleString(
        String   string)
    {
        this.string = string;
    }

    /**
     * @param string - bytes representing the string
     */
    public DERVisibleString(
        byte[]   string)
    {
        this.string = new String(string, 0);
    }

    public String getString()
    {
        return string;
    }

    public boolean equals(
        Object  o)
    {
        if ((o == null) || !(o instanceof DERVisibleString))
        {
            return false;
        }

        return this.getString().equals(((DERVisibleString)o).getString());
    }
    
    public int hashCode()
    {
        return this.getString().hashCode();
    }
        
    void encode(
        DEROutputStream  out)
        throws IOException
    {
        byte[]  bytes = new byte[string.length()];

        string.getBytes(0, string.length(), bytes, 0);

        out.writeEncoded(VISIBLE_STRING, bytes);
    }
}
