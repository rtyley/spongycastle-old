package org.bouncycastle.sasn1;

import java.io.IOException;
import java.io.InputStream;

public class DerOctetString 
    extends DerObject
    implements Asn1OctetString
{   
    protected DerOctetString(
        int         baseTag,
        byte[]      contentStream)
    {
        super(baseTag, BerTag.OCTET_STRING, contentStream);
    }
    
    public InputStream getOctetStream()
    {
        if (this.isConstructed())
        {
            return new ConstructedOctetStream(this.getRawContentStream());
        }
        else
        {
            return this.getRawContentStream();
        }
    }
    
    private class ConstructedOctetStream
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
                DerOctetString s = (DerOctetString)_aIn.readObject();

                if (s == null)
                {
                    return -1;
                }
                
                _first = false;
                _currentStream = s.getOctetStream();
            }
            
            int b = _currentStream.read();

            if (b < 0)
            {
                DerOctetString s = (DerOctetString)_aIn.readObject();
                
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
}
