/**
 * 
 */
package org.bouncycastle.cms;

import java.io.IOException;
import java.io.OutputStream;

class TeeOutputStream
    extends OutputStream
{
    private OutputStream s1;
    private OutputStream s2;

    TeeOutputStream(OutputStream dataOutputStream, OutputStream digStream)
    {
        s1 = dataOutputStream;
        s2 = digStream;
    }

    public void write(byte[] buf)
        throws IOException
    {
        s1.write(buf);
        s2.write(buf);
    }

    public void write(byte[] buf, int off, int len)
        throws IOException
    {
        s1.write(buf, off, len);
        s2.write(buf, off, len);
    }

    public void write(int b)
        throws IOException
    {
        s1.write(b);
        s2.write(b);
    }

    public void close()
        throws IOException
    {
        s1.close();
        s2.close();
    }
}