package org.bouncycastle.asn1;

import java.io.InputStream;
import java.io.IOException;
import java.io.ByteArrayOutputStream;

abstract class LimitedInputStream
        extends InputStream
{
    protected final InputStream _in;

    LimitedInputStream(
        InputStream in)
    {
        this._in = in;
    }

    byte[] toByteArray()
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        int b;
        while ((b = this.read()) >= 0)
        {
            bOut.write(b);
        }

        return bOut.toByteArray();
    }

    InputStream getUnderlyingStream()
    {
        return _in;
    }

    protected void setParentEofDetect(boolean on)
    {
        if (_in instanceof IndefiniteLengthInputStream)
        {
            ((IndefiniteLengthInputStream)_in).setEofOn00(on);
        }
    }
}
