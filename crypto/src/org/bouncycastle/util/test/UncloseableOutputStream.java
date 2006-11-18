package org.bouncycastle.util.test;

import java.io.FilterOutputStream;
import java.io.OutputStream;

public class UncloseableOutputStream extends FilterOutputStream
{
    public UncloseableOutputStream(OutputStream s)
    {
        super(s);
    }

    public void close()
    {
        throw new RuntimeException("close() called on UncloseableOutputStream");
    }
}
