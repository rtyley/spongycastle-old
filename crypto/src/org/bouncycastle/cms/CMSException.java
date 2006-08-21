package org.bouncycastle.cms;

public class CMSException
    extends Exception
{
    Exception   e;

    public CMSException(
        String name)
    {
        super(name);
    }

    public CMSException(
        String name,
        Exception e)
    {
        super(name);

        this.e = e;
    }

    public Exception getUnderlyingException()
    {
        return e;
    }
    
    public Throwable getCause()
    {
        return e;
    }
}
