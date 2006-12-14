package org.bouncycastle.sasn1;

import org.bouncycastle.asn1.DEROctetString;

import java.io.IOException;
import java.io.OutputStream;

/**
 * @deprecated use corresponsding classes in org.bouncycastle.asn1.
 */
public class BerOctetStringGenerator
    extends BerGenerator
{
    public BerOctetStringGenerator(OutputStream out) 
        throws IOException
    {
        super(out);
        
        writeBerHeader(BerTag.CONSTRUCTED | BerTag.OCTET_STRING);
    }

    public BerOctetStringGenerator(
        OutputStream out,
        int tagNo,
        boolean isExplicit) 
        throws IOException
    {
        super(out, tagNo, isExplicit);
        
        writeBerHeader(BerTag.CONSTRUCTED | BerTag.OCTET_STRING);
    }
    
    public OutputStream getOctetOutputStream()
    {
        return new BerOctetStream();
    }

    public OutputStream getOctetOutputStream(
        byte[] buf)
    {
        return new BufferedBerOctetStream(buf);
    }
    
    private class BerOctetStream
        extends OutputStream
    {
        private byte[] _buf = new byte[1];

        public void write(
            int b)
            throws IOException
        {
            _buf[0] = (byte)b;
            
            _out.write(new DEROctetString(_buf).getEncoded()); 
        }
        
        public void write(
            byte[] buf) 
            throws IOException
        {
            _out.write(new DEROctetString(buf).getEncoded());
        }
        
        public void write(
            byte[] buf,
            int    offSet,
            int    len) 
            throws IOException
        {
            byte[] bytes = new byte[len];
            
            System.arraycopy(buf, offSet, bytes, 0, len);
            
            _out.write(new DEROctetString(bytes).getEncoded());
        }
        
        public void close() 
            throws IOException
        {
             writeBerEnd();
        }
    }
    
    private class BufferedBerOctetStream
        extends OutputStream
    {
        private byte[] _buf;
        private int    _off;
    
        BufferedBerOctetStream(
            byte[] buf)
        {
            _buf = buf;
            _off = 0;
        }
        
        public void write(
            int b)
            throws IOException
        {
            _buf[_off++] = (byte)b;

            if (_off == _buf.length)
            {
                _out.write(new DEROctetString(_buf).getEncoded());
                _off = 0;
            }
        }
        
        public void close() 
            throws IOException
        {
            if (_off != 0)
            {
                byte[] bytes = new byte[_off];
                System.arraycopy(_buf, 0, bytes, 0, _off);
                
                _out.write(new DEROctetString(bytes).getEncoded());
            }
            
             writeBerEnd();
        }
    }
}
