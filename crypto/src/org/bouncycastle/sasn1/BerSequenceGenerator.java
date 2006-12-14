package org.bouncycastle.sasn1;

import java.io.IOException;
import java.io.OutputStream;

/**
 * @deprecated use corresponsding classes in org.bouncycastle.asn1.
 */
public class BerSequenceGenerator
    extends BerGenerator
{
    public BerSequenceGenerator(
        OutputStream out) 
        throws IOException
    {
        super(out);

        writeBerHeader(BerTag.CONSTRUCTED | BerTag.SEQUENCE);
    }

    public BerSequenceGenerator(
        OutputStream out,
        int tagNo,
        boolean isExplicit) 
        throws IOException
    {
        super(out, tagNo, isExplicit);
        
        writeBerHeader(BerTag.CONSTRUCTED | BerTag.SEQUENCE);
    }

    public void addObject(
        DerObject object) 
        throws IOException
    {
        _out.write(object.getEncoded());
    }
    
    public void close() 
        throws IOException
    {
        writeBerEnd();
    }
}
