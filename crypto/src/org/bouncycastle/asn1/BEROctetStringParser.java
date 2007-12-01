package org.bouncycastle.asn1;

import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class BEROctetStringParser
    implements ASN1OctetStringParser
{
    private ASN1StreamParser _parser;

    BEROctetStringParser(
        ASN1StreamParser parser)
    {
        _parser = parser;
    }

    /**
     * @deprecated will be removed
     */
    protected BEROctetStringParser(
        ASN1ObjectParser parser)
    {
        _parser = parser._aIn;
    }

    public InputStream getOctetStream()
    {
        return new ConstructedOctetStream(_parser);
    }

    public DERObject getDERObject()
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        InputStream in = this.getOctetStream();
        int         ch;

        try
        {
            while ((ch = in.read()) >= 0)
            {
                bOut.write(ch);
            }
        }
        catch (IOException e)
        {
            throw new IllegalStateException("IOException converting stream to byte array: " + e.getMessage());
        }

        return new BERConstructedOctetString(bOut.toByteArray());
    }
}
