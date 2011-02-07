package org.bouncycastle.crypto.tls;

import java.io.OutputStream;

public class TlsDeflateCompression implements TlsCompression
{
    public OutputStream compress(OutputStream output)
    {
        throw new IllegalStateException("Operation not supported");
    }

    public OutputStream decompress(OutputStream output)
    {
        throw new IllegalStateException("Operation not supported");
    }
}
