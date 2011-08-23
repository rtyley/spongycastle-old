package org.bouncycastle.asn1;

import java.io.IOException;

public class DEROctetString
    extends ASN1OctetString
{
    /**
     * @param string the octets making up the octet string.
     */
    public DEROctetString(
        byte[]  string)
    {
        super(string);
    }

    public DEROctetString(
        ASN1Encodable  obj)
    {
        super(obj);
    }

    void encode(
        DEROutputStream out)
        throws IOException
    {
        out.writeEncoded(OCTET_STRING, string);
    }

    static void encode(
        DEROutputStream derOut,
        byte[]          bytes)
        throws IOException
    {
        derOut.writeEncoded(BERTags.OCTET_STRING, bytes);
    }
}
