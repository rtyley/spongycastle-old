package org.bouncycastle.jce.provider;


class AnnotatedException 
    extends Exception
{
    private Exception _underlyingException;

    AnnotatedException(
        String string, 
        Exception e)
    {
        super(string);
        
        _underlyingException = e;
    }
    
    public AnnotatedException(
        String string)
    {
        this(string, null);
    }

    Exception getUnderlyingException()
    {
        return _underlyingException;
    }
}
