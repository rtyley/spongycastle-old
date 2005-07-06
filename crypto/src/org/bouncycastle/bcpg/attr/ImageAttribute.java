package org.bouncycastle.bcpg.attr;

import org.bouncycastle.bcpg.UserAttributeSubpacket;
import org.bouncycastle.bcpg.UserAttributeSubpacketTags;

/**
 * Basic type for a image attribute packet.
 */
public class ImageAttribute 
    extends UserAttributeSubpacket
{        
    private int     hdrLength;
    private int     version;
    private int     encoding;
    private byte[]  imageData;
    
    public ImageAttribute(
        byte[]    data)
    {
        super(UserAttributeSubpacketTags.IMAGE_ATTRIBUTE, data);
        
        hdrLength = ((data[1] & 0xff) << 8) | (data[0] & 0xff);
        version = data[2] & 0xff;
        encoding = data[3] & 0xff;
        
        imageData = new byte[data.length - hdrLength];
        System.arraycopy(data, hdrLength, imageData, 0, imageData.length);
    }
    
    public int version()
    {
        return version;
    }
    
    public int getEncoding()
    {
        return encoding;
    }
    
    public byte[] getImageData()
    {
        return imageData;
    }
}
