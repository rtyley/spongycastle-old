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
    }

    public int read()
        throws IOException
    {
        if (_length > 0)
        {
            int b = _in.read();

            if (b < 0)
            {
                throw new EOFException();
            }

            --_length;
            return b;
        }

        setParentEofDetect(true);

        return -1;
    }

    public int read(byte[] buf, int off, int len)
        throws IOException
    {
        if (_length > 0)
        {
            int toRead = Math.min(len, _length);
            int numRead = _in.read(buf, off, toRead);

            if (numRead < 0)
            {
                throw new EOFException();
            }

            _length -= numRead;
            return numRead;
        }

        setParentEofDetect(true);

        return -1;
    }

    byte[] toByteArray()
        throws IOException
    {
        byte[] bytes;
        if (_length > 0)
        {
            bytes = new byte[_length];
            if (Streams.readFully(_in, bytes) < _length)
            {
                throw new EOFException();
            }
            _length = 0;
        }
        else
        {
            bytes = EMPTY_BYTES;
        }

        setParentEofDetect(true);

        return bytes;
    }
}
