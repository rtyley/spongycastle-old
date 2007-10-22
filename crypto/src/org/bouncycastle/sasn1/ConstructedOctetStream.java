package org.bouncycastle.sasn1;

import java.io.IOException;
import java.io.InputStream;

/**
 * @deprecated use corresponding classes in org.bouncycastle.asn1.
 */
class ConstructedOctetStream
    extends InputStream
{
    private final Asn1InputStream _aIn;
    
    private boolean               _first = true;
    private InputStream           _currentStream;
    
    ConstructedOctetStream(
        InputStream in)
    {
        _aIn = new Asn1InputStream(in);
    }
    
    public int read() 
        throws IOException
    {
        if (_first)
        {
            Asn1OctetString s = (Asn1OctetString)_aIn.readObject();
    
            if (s == null)
            {
                return -1;
            }
            
            _first = false;
            _currentStream = s.getOctetStream();
        }
        else if (_currentStream == null)
        {
            return -1;
        }
            
        int b = _currentStream.read();
    
        if (b < 0)
        {
            Asn1OctetString s = (Asn1OctetString)_aIn.readObject();
            
            if (s == null)
            {
                _currentStream = null;
                
                return -1;
            }
            
            _currentStream = s.getOctetStream();
            
            return _currentStream.read();
        }
        else
        {
            return b;
        }
    }
}
