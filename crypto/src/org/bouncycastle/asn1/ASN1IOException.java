package org.bouncycastle.asn1;

import java.io.IOException;

public class ASN1IOException
    extends IOException
{
    private Throwable cause;

    ASN1IOException(String message)
    {
        super(message);
    }

    ASN1IOException(String message, Throwable cause)
    {
        super(message);
        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}
