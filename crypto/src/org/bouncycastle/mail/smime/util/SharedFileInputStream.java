package org.bouncycastle.mail.smime.util;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.mail.internet.SharedInputStream;

public class SharedFileInputStream extends FilterInputStream
    implements SharedInputStream
{
    private final String _fileName;
    private final long _start;
    private final long _finish;
    
    private long _position;
    
    public SharedFileInputStream(
        String fileName) 
        throws IOException
    {
        this(fileName, 0, -1);
    }
    
    private SharedFileInputStream(
        String fileName,
        long start,
        long finish)
        throws IOException
    {
        super(new BufferedInputStream(new FileInputStream(fileName)));
        
        _fileName = fileName;
        _start = start;
        _finish = finish;
        
        in.skip(start);
    }
    
    public long getPosition()
    {
        return _position;
    }

    public InputStream newStream(long start, long finish)
    {
        try
        {
        if (finish < 0)
        {
            return new SharedFileInputStream(_fileName, _start + start, _finish);
        }
        else
        {
            return new SharedFileInputStream(_fileName, _start + start, finish);
        }
        }
        catch (IOException e)
        {
            throw new IllegalStateException("unable to create shared stream: " + e);
        }
    }
    
    public int read() throws IOException
    {
        if (_position == _finish)
        {
            return -1;
        }
        
        _position++;
        return in.read();
    }
}