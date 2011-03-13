package org.spongycastle.asn1;

import java.io.IOException;

/**
 * DER BMPString object.
 */
public class DERBMPString
    extends DERObject implements DERString
{
    String  string;

    public DERBMPString(
        String   string)
    {
        this.string = string;
    }

    /**
     * @param string - bytes representing the string
     */
    public DERBMPString(
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
        if (!(o instanceof DERBMPString))
        {
            return false;
        }

        DERBMPString  s = (DERBMPString)o;

        return this.getString().equals(s.getString());
    }
    
    void encode(
        DEROutputStream  out)
        throws IOException
    {
        byte[]  bytes = new byte[string.length()];

        string.getBytes(0, string.length(), bytes, 0);

        out.writeEncoded(BMP_STRING, bytes);
    }
}
