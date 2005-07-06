package org.bouncycastle.bcpg;

import java.io.IOException;

/**
 * Basic type for a user ID packet.
 */
public class UserIDPacket 
    extends ContainedPacket
{    
    private byte[]    idData;
    
    public UserIDPacket(
        BCPGInputStream  in)
        throws IOException
    {
        idData = new byte[in.available()];
        in.readFully(idData);
    }
    
    public UserIDPacket(
        String    id)
    {
        this.idData = new byte[id.length()];
        
        for (int i = 0; i != id.length(); i++)
        {
            idData[i] = (byte)id.charAt(i);
        }
        
    }
    public String getID()
    {
        char[]    chars = new char[idData.length];
        
        for (int i = 0; i != chars.length; i++)
        {
            chars[i] = (char)(idData[i] & 0xff);
        }
        
        return new String(chars);
    }
    
    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        out.writePacket(USER_ID, idData, true);
    }
}
