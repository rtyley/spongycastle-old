package org.bouncycastle.cms;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * a holding class for a byte array of data to be processed.
 */
public class CMSProcessableByteArray
    implements CMSProcessable, CMSReadable
{
    private byte[]  bytes;

    public CMSProcessableByteArray(
        byte[]  bytes)
    {
        this.bytes = bytes;
    }

    public InputStream read()
    {
        return new ByteArrayInputStream(bytes);
    }

    public void write(OutputStream zOut)
        throws IOException, CMSException
    {
        zOut.write(bytes);
    }

    public Object getContent()
    {
        return bytes.clone();
    }
}
