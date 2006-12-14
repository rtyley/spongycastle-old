package org.bouncycastle.sasn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * @deprecated use corresponsding classes in org.bouncycastle.asn1.
 */
public class DerSequenceGenerator
    extends DerGenerator
{
    private final ByteArrayOutputStream _bOut = new ByteArrayOutputStream();

    public DerSequenceGenerator(
        OutputStream out)
        throws IOException
    {
        super(out);
    }

    public DerSequenceGenerator(
        OutputStream out,
        int          tagNo,
        boolean      isExplicit)
        throws IOException
    {
        super(out, tagNo, isExplicit);
    }

    public void addObject(
        DerObject object) 
        throws IOException
    {
        _bOut.write(object.getEncoded());
    }
    
    public OutputStream getRawOutputStream()
    {
        return _bOut;
    }
    
    public void close() 
        throws IOException
    {
        writeDerEncoded(BerTag.CONSTRUCTED | BerTag.SEQUENCE, _bOut.toByteArray());
    }
}
