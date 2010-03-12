package org.bouncycastle.cms;

import java.io.IOException;
import java.io.OutputStream;

class TeeOutputStream
    extends OutputStream
{
    private OutputStream output1;
    private OutputStream output2;

    TeeOutputStream(OutputStream output1, OutputStream output2)
    {
        this.output1 = output1;
        this.output2 = output2;
    }

    public void write(byte[] buf)
        throws IOException
    {
        this.output1.write(buf);
        this.output2.write(buf);
    }

    public void write(byte[] buf, int off, int len)
        throws IOException
    {
        this.output1.write(buf, off, len);
        this.output2.write(buf, off, len);
    }

    public void write(int b)
        throws IOException
    {
        this.output1.write(b);
        this.output2.write(b);
    }

    public void close()
        throws IOException
    {
        this.output1.close();
        this.output2.close();
    }
}