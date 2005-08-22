package org.bouncycastle.sasn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

abstract class LimitedInputStream
    extends InputStream
{
    protected final InputStream _in;
    
    LimitedInputStream(
        InputStream in)
    {
         this._in = in;
    }
    
    byte[] toByteArray() 
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        int b = 0;
        while ((b = this.read()) >= 0)
        {
            bOut.write(b);
        }
        
        return bOut.toByteArray();
    }
    
    InputStream getUnderlyingStream()
    {
        return _in;
    }
}
