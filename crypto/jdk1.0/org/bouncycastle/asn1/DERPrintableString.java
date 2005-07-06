package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * DER PrintableString object.
 */
public class DERPrintableString
    extends DERObject
{
    String  string;

    public DERPrintableString(
        String   string)
    {
        this.string = string;
    }

    /**
     * @param string - bytes representing the string
     */
    public DERPrintableString(
        byte[]   string)
    {
        this.string = new String(string, 0);
    }

    public String getString()
    {
        return string;
    }

    public int hashCode()
    {
        return this.getString().hashCode();
    }

    public boolean equals(
        Object  o)
    {
        if (!(o instanceof DERPrintableString))
        {
            return false;
        }

        DERPrintableString  s = (DERPrintableString)o;

        return this.getString().equals(s.getString());
    }
    
    void encode(
        DEROutputStream  out)
        throws IOException
    {
        byte[]  bytes = new byte[string.length()];

        string.getBytes(0, string.length(), bytes, 0);

        out.writeEncoded(PRINTABLE_STRING, bytes);
    }
}
