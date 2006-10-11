package org.bouncycastle.sasn1;

import java.io.OutputStream;

/**
 * @deprecated use org.bouncycastle.asn1.ASN1Generator
 */
public abstract class Asn1Generator
{
    protected OutputStream _out;
    
    public Asn1Generator(OutputStream out)
    {
        _out = out;
    }
    
    public abstract OutputStream getRawOutputStream();
}
