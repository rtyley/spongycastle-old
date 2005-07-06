package org.bouncycastle.bcpg;

import java.io.*;

/**
 * generic literal data packet.
 */
public class LiteralDataPacket 
    extends InputStreamPacket
{
    int     format;
    char[]  fileName;
    long    modDate;
    
    LiteralDataPacket(
        BCPGInputStream    in)
        throws IOException
    {
        super(in);
        
        format = in.read();    
        int    l = in.read();
        
        fileName = new char[l];
        for (int i = 0; i != fileName.length; i++)
        {
            fileName[i] = (char)in.read();
        }
        
        modDate = ((long)in.read() << 24) | (in.read() << 16) | (in.read() << 8) | in.read();
    }
    
    /**
     * return the format tag value.
     * 
     * @return format tag value.
     */
    public int getFormat()
    {
        return format;
    }

    /**
     * Return the modification time of the file in milli-seconds.
     * 
     * @return the modification time in millis
     */
    public long getModificationTime()
    {
        return modDate * 1000L;
    }
    
    /**
     * @return filename
     */
    public String getFileName()
    {
        return new String(fileName);
    }
}
