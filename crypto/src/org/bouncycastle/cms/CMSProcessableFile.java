package org.bouncycastle.cms;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * a holding class for a file of data to be processed.
 */
public class CMSProcessableFile
    implements CMSProcessable, CMSReadable
{
    private static final int DEFAULT_BUF_SIZE = 32 * 1024;
    
    private final File   _file;
    private final byte[] _buf;

    public CMSProcessableFile(
        File file)
    {
        this(file, DEFAULT_BUF_SIZE);
    }
    
    public CMSProcessableFile(
        File file,
        int  bufSize)
    {
        _file = file;
        _buf = new byte[bufSize];
    }

    public InputStream read()
        throws IOException, CMSException
    {
        return new BufferedInputStream(new FileInputStream(_file), DEFAULT_BUF_SIZE);
    }

    public void write(OutputStream zOut)
        throws IOException, CMSException
    {
        FileInputStream     fIn = new FileInputStream(_file);
        int                 len;
        
        while ((len = fIn.read(_buf, 0, _buf.length)) > 0)
        {
            zOut.write(_buf, 0, len);
        }
        
        fIn.close();
    }

    /**
     * Return the file handle.
     */
    public Object getContent()
    {
        return _file;
    }
}
