package org.bouncycastle.asn1;

import org.bouncycastle.util.io.Streams;

import java.io.EOFException;
import java.io.InputStream;
import java.io.IOException;

class DefiniteLengthInputStream
        extends LimitedInputStream
{
    private static final byte[] EMPTY_BYTES = new byte[0];

    private int _length;

    DefiniteLengthInputStream(
        InputStream in,
        int         length)
    {
        super(in);

        if (length < 0)
        {
            throw new IllegalArgumentException("negative lengths not allowed");
        }

        this._length = length;

        if (length == 0)
        {
            setParentEofDetect(true);
        }
    }

    public int read()
        throws IOException
    {
        if (_length == 0)
        {
            return -1;
        }

        int b = _in.read();

        if (b < 0)
        {
            throw new EOFException();
        }

        if (--_length == 0)
        {
            setParentEofDetect(true);
        }

        return b;
    }

    public int read(byte[] buf, int off, int len)
        throws IOException
    {
        if (_length == 0)
        {
            return -1;
        }

        int toRead = Math.min(len, _length);
        int numRead = _in.read(buf, off, toRead);

        if (numRead < 0)
        {
            throw new EOFException();
        }

        if ((_length -= numRead) == 0)
        {
            setParentEofDetect(true);
        }

        return numRead;
    }

    byte[] toByteArray()
        throws IOException
    {
        if (_length == 0)
        {
            return EMPTY_BYTES;
        }

        byte[] bytes = new byte[_length];
        if (Streams.readFully(_in, bytes) < _length)
        {
            throw new EOFException();
        }
        _length = 0;
        setParentEofDetect(true);
        return bytes;
    }
}
