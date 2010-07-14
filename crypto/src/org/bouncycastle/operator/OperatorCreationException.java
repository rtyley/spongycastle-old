package org.bouncycastle.operator;

public class OperatorCreationException
    extends Exception
{
    private Throwable cause;

    public OperatorCreationException(String msg, Throwable cause)
    {
        super(msg);

        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}
