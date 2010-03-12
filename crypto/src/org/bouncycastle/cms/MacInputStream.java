package org.bouncycastle.cms;

import java.io.IOException;
import java.io.InputStream;

import javax.crypto.Mac;

class MacInputStream
    extends InputStream
{
    private final InputStream inStream;
    private final Mac mac;

    MacInputStream(InputStream inStream, Mac mac)
    {
        this.inStream = inStream;
        this.mac = mac;
    }

    public int read(byte[] buf)
        throws IOException
    {
        return read(buf, 0, buf.length);
    }

    public int read(byte[] buf, int off, int len)
        throws IOException
    {
        int i = inStream.read(buf, off, len);

        if (i > 0)
        {
            mac.update(buf, off, i);
        }

        return i;
    }

    public int read()
        throws IOException
    {
        int i = inStream.read();

        if (i > 0)
        {
            mac.update((byte)i);
        }

        return i;
    }

    public byte[] getMac()
    {
        return mac.doFinal();
    }
}