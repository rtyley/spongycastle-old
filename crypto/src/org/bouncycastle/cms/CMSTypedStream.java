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
        this._oid = oid;
        this._in = in;
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
    }
}
