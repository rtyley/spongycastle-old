package org.bouncycastle.crypto.tls;

import java.io.OutputStream;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterOutputStream;

public class TlsDeflateCompression implements TlsCompression
{
    public OutputStream compress(OutputStream output)
    {
        return new DeflaterOutputStream(output);
    }

    public OutputStream decompress(OutputStream output)
    {
        return new InflaterOutputStream(output);
    }
}
