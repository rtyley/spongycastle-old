package org.bouncycastle.sasn1;

import java.io.OutputStream;

public abstract class Asn1Generator
{
    protected OutputStream _out;
    
    public Asn1Generator(OutputStream out)
    {
        _out = out;
    }
    
    public abstract OutputStream getRawOutputStream();
}
