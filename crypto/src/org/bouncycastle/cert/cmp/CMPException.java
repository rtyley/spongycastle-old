package org.bouncycastle.cert.cmp;

public class CMPException
    extends Exception
{
    private Throwable cause;

    public CMPException(String msg, Throwable cause)
    {
        super(msg);

        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}