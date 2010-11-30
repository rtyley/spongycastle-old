package org.bouncycastle.cert.pkcs;


public class PKCSException
    extends Exception
{
    private Throwable cause;

    public PKCSException(String msg, Throwable cause)
    {
        super(msg);

        this.cause = cause;
    }

    public PKCSException(String msg)
    {
        super(msg);
    }

    public Throwable getCause()
    {
        return cause;
    }
}
