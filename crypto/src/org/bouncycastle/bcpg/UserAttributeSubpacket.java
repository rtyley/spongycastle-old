package org.bouncycastle.bcpg;

import java.io.*;

/**
 * Basic type for a PGP Signature sub-packet.
 */
public class UserAttributeSubpacket 
{
    int                type;
    
    protected byte[]   data;
    
    protected UserAttributeSubpacket(
        int            type,
        byte[]         data)
    {    
        this.type = type;
        this.data = data;
    }
    
    public int getType()
    {
        return type;
    }
    
    /**
     * return the generic data making up the packet.
     */
    public byte[] getData()
    {
        return data;
    }

    public void encode(
        OutputStream    out)
        throws IOException
    {
        int    bodyLen = data.length + 1;
        
        if (bodyLen < 192)
        {
            out.write((byte)bodyLen);
        }
        else if (bodyLen <= 8383)
        {
            bodyLen -= 192;
            
            out.write((byte)(((bodyLen >> 8) & 0xff) + 192));
            out.write((byte)bodyLen);
        }
        else
        {
            out.write(0xff);
            out.write((byte)(bodyLen >> 24));
            out.write((byte)(bodyLen >> 16));
            out.write((byte)(bodyLen >> 8));
            out.write((byte)bodyLen);
        }

        out.write(type);        
        out.write(data);
    }
    
    public boolean equals(
        Object o)
    {
        if (o == this)
        {
            return true;
        }
        
        if (o instanceof UserAttributeSubpacket)
        {
            UserAttributeSubpacket   other = (UserAttributeSubpacket)o;
            
            if (other.type != this.type)
            {
                return false;
            }
            
            if (other.data.length != this.data.length)
            {
                return false;
            }
            
            for (int i = 0; i != this.data.length; i++)
            {
                if (this.data[i] != other.data[i])
                {
                    return false;
                }
            }
            
            return true;
        }
        
        return false;
    }
    
    public int hashCode()
    {
        int    code = this.type;
        
        for (int i = 0; i != this.data.length; i++)
        {
            code ^= (this.data[i] & 0xff) << (8 * (i % 4));
        }
        
        return code;
    }
}
