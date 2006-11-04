package org.bouncycastle.util;

public class StreamParsingException 
    extends Exception
{
    Exception _e;

    public StreamParsingException(String message, Exception e)
    {
        super(message);
        _e = e;
    }

    public Throwable getCause()
    {
        return _e;
    }
}
