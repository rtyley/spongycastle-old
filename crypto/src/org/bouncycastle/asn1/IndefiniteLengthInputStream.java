package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.InputStream;

class IndefiniteLengthInputStream
    extends LimitedInputStream
{
    private int _b1;
    private int _b2;
    private boolean _eofReached = false;
    private boolean _eofOn00 = true;

    IndefiniteLengthInputStream(
        InputStream in)
        throws IOException
    {
        super(in);

        _b1 = in.read();
        _b2 = in.read();
        _eofReached = (_b2 < 0);
    }

    void setEofOn00(
        boolean eofOn00)
    {
        _eofOn00 = eofOn00;
    }

    void checkForEof()
        throws IOException
    {
        if (_eofOn00 && (_b1 == 0x00 && _b2 == 0x00))
        {
            _eofReached = true;
            setParentEofDetect(true);
        }
    }

    public int read()
        throws IOException
    {
        checkForEof();

        if (_eofReached)
        {
            return -1;
        }

        int b = _in.read();

        //
        // strictly speaking we should return b1 and b2, but if this happens the stream
        // is corrupted so we are already in trouble.
        //
        if (b < 0)
        {
            _eofReached = true;

            return -1;
        }

        int v = _b1;

        _b1 = _b2;
        _b2 = b;

        return v;
    }
}
