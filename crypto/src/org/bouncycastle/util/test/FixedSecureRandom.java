package org.bouncycastle.util.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

public class FixedSecureRandom
    extends SecureRandom
{
    private final byte[] _data;
    
    private int          _index;
    
    public FixedSecureRandom(byte[] value)
    {
        this(new byte[][] { value });
    }
    
    public FixedSecureRandom(byte[][] values)
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        for (int i = 0; i != values.length; i++)
        {
            try
            {
                bOut.write(values[i]);
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("can't save value array.");
            }
        }
        
        _data = bOut.toByteArray();
    }

    public void nextBytes(byte[] bytes)
    {
        System.arraycopy(_data, _index, bytes, 0, bytes.length);
        
        _index += bytes.length;
    }
    
    //
    // classpath's implementation of SecureRandom doesn't currently go back to nextBytes
    // when next is called. We can't override next as it's a final method.
    //
    public int nextInt()
    {
        int val = _data[_index++] << 24;
        
        val |= (_data[_index++] & 0xff) << 16;
        val |= (_data[_index++] & 0xff) << 8;
        val |= _data[_index++] & 0xff;
        
        return val;
    }
}
