package org.bouncycastle.util.io;

public class StreamOverflowException
    extends RuntimeException
{
    private final byte[] data;

    public StreamOverflowException(String msg)
    {
        super(msg);
        this.data = null;
    }

    public StreamOverflowException(String msg, byte[] data)
    {
        super(msg);
        this.data = data;
    }

    /**
     * Return the data read before the exception occured if available.
     *
     * @return data read if available, null otherwise.
     */
    public byte[] getData()
    {
        return data;
    }
}
