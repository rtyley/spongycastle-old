package org.bouncycastle.sasn1;

import java.io.IOException;
import java.io.InputStream;

class DefiniteLengthInputStream
    extends LimitedInputStream
{
    private int               _length;
    
    DefiniteLengthInputStream(
        InputStream in,
        int         length)
    {
        super(in);
        
        this._length = length;
        
        if (_in instanceof IndefiniteLengthInputStream)
        {
            ((IndefiniteLengthInputStream)_in).setEofOn00(false);
        }
    }
    
    public int read()
        throws IOException
    {
        if (_length-- > 0)
        {
            return _in.read();
        }
        else
        {
            if (_in instanceof IndefiniteLengthInputStream)
            {
                IndefiniteLengthInputStream parent = (IndefiniteLengthInputStream)_in;
                
                parent.setEofOn00(true);
            }
            
            return -1;
        }
    }
}
