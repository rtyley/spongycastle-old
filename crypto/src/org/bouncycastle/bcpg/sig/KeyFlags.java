package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * Packet holding the key flag values.
 */
public class KeyFlags 
    extends SignatureSubpacket
{    
    private static final byte[] intToByteArray(
        int    v)
    {
        byte[]    data = new byte[1];
        
        data[0] = (byte)v;
        
        return data;
    }
    
    public KeyFlags(
        boolean    critical,
        byte[]     data)
    {
        super(SignatureSubpacketTags.KEY_FLAGS, critical, data);
    }
    
    public KeyFlags(
        boolean    critical,
        int        flags)
    {
        super(SignatureSubpacketTags.KEY_FLAGS, critical, intToByteArray(flags));
    }
    
    public int getFlags()
    {    
        return data[0] & 0xff;
    }
}
