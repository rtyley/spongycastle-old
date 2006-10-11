package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.DEROctetString;

public class BEROctetStringGenerator
    extends BERGenerator
{
    public BEROctetStringGenerator(OutputStream out) 
        throws IOException
    {
        super(out);
        
        writeBERHeader(DERTags.CONSTRUCTED | DERTags.OCTET_STRING);
    }

    public BEROctetStringGenerator(
        OutputStream out,
        int tagNo,
        boolean isExplicit) 
        throws IOException
    {
        super(out, tagNo, isExplicit);
        
        writeBERHeader(DERTags.CONSTRUCTED | DERTags.OCTET_STRING);
    }
    
    public OutputStream getOctetOutputStream()
    {
        return new BEROctetStream();
    }

    public OutputStream getOctetOutputStream(
        byte[] buf)
    {
        return new BufferedBEROctetStream(buf);
    }
    
    private class BEROctetStream
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
             writeBEREnd();
        }
    }
    
    private class BufferedBEROctetStream
        extends OutputStream
    {
        private byte[] _buf;
        private int    _off;
    
        BufferedBEROctetStream(
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
            
             writeBEREnd();
        }
    }
}
