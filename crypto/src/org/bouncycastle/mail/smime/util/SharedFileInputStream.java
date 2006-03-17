package org.bouncycastle.mail.smime.util;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.mail.internet.SharedInputStream;

public class SharedFileInputStream 
    extends FilterInputStream
    implements SharedInputStream
{
    private final File _file;
    private final long _start;
    private final long _length;
    
    private long _position;
    private long _markedPosition;
    
    private List _subStreams = new LinkedList();
    
    public SharedFileInputStream(
        String fileName) 
        throws IOException
    {
        this(new File(fileName), 0, -1);
    }
    
    public SharedFileInputStream(
        File file) 
        throws IOException
    {
        this(file, 0, -1);
    }
    
    private SharedFileInputStream(
        File file,
        long start,
        long length)
        throws IOException
    {
        super(new BufferedInputStream(new FileInputStream(file)));
        
        _file = file;
        _start = start;
        _length = length;
        
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
            SharedFileInputStream stream;
            
            if (finish < 0)
            {
                if (_length > 0)
                {
                    stream = new SharedFileInputStream(_file, _start + start, _length - start);
                }
                else
                {
                    stream = new SharedFileInputStream(_file, _start + start, -1);
                }
            }
            else
            {
                stream = new SharedFileInputStream(_file, _start + start, finish - start);
            }
            
            _subStreams.add(stream);
            
            return stream;
        }
        catch (IOException e)
        {
            throw new IllegalStateException("unable to create shared stream: " + e);
        }
    }
    
    public int read(
        byte[] buf) 
        throws IOException
    {
        return this.read(buf, 0, buf.length);
    }
    
    public int read(
        byte[] buf, 
        int off, 
        int len) 
        throws IOException
    {
        int count = 0;
        
        if (len == 0)
        {
            return 0;
        }
        
        while (count < len)
        {
            int ch = this.read();
            
            if (ch < 0)
            {
                break;
            }
            
            buf[off + count] = (byte)ch;
            count++;
        }
        
        if (count == 0)
        {
            return -1;  // EOF
        }
        
        return count;
    }
    
    public int read() 
        throws IOException
    {
        if (_position == _length)
        {
            return -1;
        }

        _position++;
        return in.read();
    }
    
    public void mark(
        int readLimit)
    {
        _markedPosition = _position;
        in.mark(readLimit);
    }
    
    public void reset() 
        throws IOException
    {
        _position = _markedPosition;
        in.reset();
    }
    
    /**
     * Close of this stream and any substreams that have been created from it.
     * @throws IOException on problem closing the main stream.
     */
    public void dispose() 
        throws IOException 
    {
        Iterator it = _subStreams.iterator();
        
        while (it.hasNext())
        {
            try
            {
                ((SharedFileInputStream)it.next()).dispose();
            }
            catch (IOException e)
            {
                // ignore
            }
        }

        in.close();
    }
}