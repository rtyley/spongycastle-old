package org.bouncycastle.cms;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

public class CMSTypedStream
{
    private static final int BUF_SIZ = 32 * 1024;
    
    private final String      _oid;
    private final InputStream _in;
    
    public CMSTypedStream(
        InputStream in)
    {
        this(PKCSObjectIdentifiers.data.getId(), in);
    }
    
    public CMSTypedStream(
        String      oid,
        InputStream in)
    {
        _oid = oid;
        _in = new FullReaderStream(in);
    }

    public String getContentType()
    {
        return _oid;
    }
    
    public InputStream getContentStream()
    {
        return _in;
    }

    public void drain() 
        throws IOException
    {
        byte[] buf = new byte[BUF_SIZ];
        
        while ((_in.read(buf, 0, buf.length) == buf.length))
        {
            // keep going...
        }
        
        _in.close();
    }
    
    private class FullReaderStream
        extends InputStream
    {
        InputStream _in;
        
        FullReaderStream(
            InputStream in)
        {
            _in = in;
        }
        
        public int read() 
            throws IOException
        {
            return _in.read();
        }
        
        public int read(
            byte[] buf,
            int    off,
            int    len) 
            throws IOException
        {
            int    rd = 0;
            int    total = 0;
            
            while (len != 0 && (rd = _in.read(buf, off, len)) > 0)
            {
                off += rd;
                len -= rd;
                total += rd;
            }
            
            if (total > 0)
            {
                return total;
            }
            else
            {
                return -1;
            }
        }
        
        public void close() 
            throws IOException
        {
            _in.close();
        }
    }
}
