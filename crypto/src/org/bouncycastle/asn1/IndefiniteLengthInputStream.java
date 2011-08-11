package org.bouncycastle.asn1;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

class IndefiniteLengthInputStream
    extends LimitedInputStream
{
    private int _lookAhead;
    private boolean _eofOn00 = true;

    IndefiniteLengthInputStream(
        InputStream in,
        int         limit)
        throws IOException
    {
        super(in, limit);

        _lookAhead = requireByte();
        checkForEof();
    }

    void setEofOn00(
        boolean eofOn00)
        throws IOException
    {
        _eofOn00 = eofOn00;
        checkForEof();
    }

    private boolean checkForEof()
        throws IOException
    {
        if (_lookAhead == 0x00 && _eofOn00)
        {
            int extra = requireByte();
            if (extra != 0)
            {
                throw new IOException("malformed end-of-contents marker");
            }

            _lookAhead = -1;            
            setParentEofDetect(true);
        }
        return _lookAhead < 0;
    }

    public int read(byte[] b, int off, int len)
        throws IOException
    {
        // Can't use optimisation if we are checking for 00
        if (_eofOn00 || len <= 1)
        {
            return super.read(b, off, len);
        }

        if (_lookAhead < 0)
        {
            return -1;
        }

        int numRead = _in.read(b, off + 1, len - 1);

        if (numRead < 0)
        {
            // Corrupted stream
            throw new EOFException();
        }

        b[off] = (byte)_lookAhead;
        _lookAhead = requireByte();

        return numRead + 1;
    }

    public int read()
        throws IOException
    {
        if (checkForEof())
        {
            return -1;
        }

        int result = _lookAhead;
        _lookAhead = requireByte();
        return result;
    }

    private int requireByte() throws IOException
    {
        int b = _in.read();
        if (b < 0)
        {
            // Corrupted stream
            throw new EOFException();
        }
        return b;
    }
}
