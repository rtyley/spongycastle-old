package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.MaxBytesExceededException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Strings;

/**
 * Implementation of Daniel J. Bernstein's Salsa20 stream cipher, Snuffle 2005
 */

public class Salsa20Engine
    implements StreamCipher
{
    /** Constants */
    private final static int stateSize = 16; // 16, 32 bit ints = 64 bytes
    
    private final static byte[]
        sigma = Strings.toByteArray("expand 32-byte k"),
        tau   = Strings.toByteArray("expand 16-byte k");

    /*
     * variables to hold the state of the engine
     * during encryption and decryption
     */
    private int         index = 0;
    private int[]       engineState = null; // state
    private byte[]      keyStream   = new byte[stateSize>>2], // expanded state, 64 bytes
                        workingKey  = null,
                        workingIV   = null;
    private boolean     initialised = false;
    
    /*
     * internal counter
     */
    private int cW0, cW1, cW2;
    

    /**
     * initialise a Salsa20 cipher.
     *
     * @param forEncryption whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    public void init(
        boolean             forEncryption, 
        CipherParameters     params)
    {
        CipherParameters keyParam = params;
        if (params instanceof ParametersWithIV)
        {
            workingIV = ((ParametersWithIV)params).getIV();
            keyParam = ((ParametersWithIV)params).getParameters();
        }
        
        if (keyParam instanceof KeyParameter)
        {
            /* 
             * Salsa20 encryption and decryption is completely
             * symmetrical, so the 'forEncryption' is 
             * irrelevant. (Like 90% of stream ciphers)
             */
            workingKey = ((KeyParameter)keyParam).getKey();
            setKey(workingKey, workingIV);

            return;
        }

        throw new IllegalArgumentException("invalid parameter passed to Salsa20 init - " + params.getClass().getName());
    }

    public String getAlgorithmName()
    {
        return "Salsa20";
    }

    public byte returnByte(byte in)
    {
        if (limitExceeded())
        {
            throw new MaxBytesExceededException("2^70 byte limit per IV; Change IV");
        }
        
        if (index == 0)
        {
            keyStream = salsa20WordToByte(engineState);
            engineState[8]++;
            if (engineState[8] == 0)
            {
                engineState[9]++;
            }
        }
        byte out = (byte)(keyStream[index]^in);
        index = (index + 1) & 63;
    
        return out;
    }

    public void processBytes(
        byte[]     in, 
        int     inOff, 
        int     len, 
        byte[]     out, 
        int     outOff)
    {
        if (!initialised)
        {
            throw new IllegalStateException(getAlgorithmName()+" not initialised");
        }
        
        if ((inOff + len) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        if ((outOff + len) > out.length)
        {
            throw new DataLengthException("output buffer too short");
        }
        
        for (int i = 0; i < len; i++)
        {
            if (limitExceeded())
            {
                throw new MaxBytesExceededException("2^70 byte limit per IV; Change IV");
            }
            
            if (index == 0)
            {
                keyStream = salsa20WordToByte(engineState);
                engineState[8]++;
                if (engineState[8] == 0)
                {
                    engineState[9]++;
                }
            }
            out[i+outOff] = (byte)(keyStream[index]^in[i+inOff]);
            index = (index + 1) & 63;
        }
    }

    public void reset()
    {
        setKey(workingKey, workingIV);
    }

    // Private implementation

    private void setKey(byte[] keyBytes, byte[] ivBytes)
    {
        workingKey = keyBytes;
        workingIV  = ivBytes;

        index = 0;
        resetCounter();

        if (engineState == null)
        {
            engineState = new int[stateSize];
        }

        int offset = 0;
        byte[] constants;
        
        // Key
        engineState[1] = byteToIntLittle(workingKey, 0);
        engineState[2] = byteToIntLittle(workingKey, 4);
        engineState[3] = byteToIntLittle(workingKey, 8);
        engineState[4] = byteToIntLittle(workingKey, 12);
        
        if (workingKey.length == 32)
        {
            constants = sigma;
            offset = 16;
        }
        else
        {
            constants = tau;
        }
        
        engineState[11] = byteToIntLittle(workingKey, offset);
        engineState[12] = byteToIntLittle(workingKey, offset+4);
        engineState[13] = byteToIntLittle(workingKey, offset+8);
        engineState[14] = byteToIntLittle(workingKey, offset+12);
        engineState[0 ] = byteToIntLittle(constants, 0);
        engineState[5 ] = byteToIntLittle(constants, 4);
        engineState[10] = byteToIntLittle(constants, 8);
        engineState[15] = byteToIntLittle(constants, 12);
        
        // IV
        engineState[6] = byteToIntLittle(workingIV, 0);
        engineState[7] = byteToIntLittle(workingIV, 4);
        engineState[8] = engineState[9] = 0;
        
        initialised = true;
    }
    
    /**
     * Salsa20 function
     *
     * @param   input   input data
     *
     * @return  keystream
     */    
    private byte[] salsa20WordToByte(int[] input)
    {
        int[] x = new int[input.length];
        System.arraycopy(input, 0, x, 0, input.length);
        
        int i = 0;
        while (i++ < 10)
        {
            x[ 4] ^= rotl((x[ 0]+x[12]), 7);
            x[ 8] ^= rotl((x[ 4]+x[ 0]), 9);
            x[12] ^= rotl((x[ 8]+x[ 4]),13);
            x[ 0] ^= rotl((x[12]+x[ 8]),18);
            x[ 9] ^= rotl((x[ 5]+x[ 1]), 7);
            x[13] ^= rotl((x[ 9]+x[ 5]), 9);
            x[ 1] ^= rotl((x[13]+x[ 9]),13);
            x[ 5] ^= rotl((x[ 1]+x[13]),18);
            x[14] ^= rotl((x[10]+x[ 6]), 7);
            x[ 2] ^= rotl((x[14]+x[10]), 9);
            x[ 6] ^= rotl((x[ 2]+x[14]),13);
            x[10] ^= rotl((x[ 6]+x[ 2]),18);
            x[ 3] ^= rotl((x[15]+x[11]), 7);
            x[ 7] ^= rotl((x[ 3]+x[15]), 9);
            x[11] ^= rotl((x[ 7]+x[ 3]),13);
            x[15] ^= rotl((x[11]+x[ 7]),18);
            x[ 1] ^= rotl((x[ 0]+x[ 3]), 7);
            x[ 2] ^= rotl((x[ 1]+x[ 0]), 9);
            x[ 3] ^= rotl((x[ 2]+x[ 1]),13);
            x[ 0] ^= rotl((x[ 3]+x[ 2]),18);
            x[ 6] ^= rotl((x[ 5]+x[ 4]), 7);
            x[ 7] ^= rotl((x[ 6]+x[ 5]), 9);
            x[ 4] ^= rotl((x[ 7]+x[ 6]),13);
            x[ 5] ^= rotl((x[ 4]+x[ 7]),18);
            x[11] ^= rotl((x[10]+x[ 9]), 7);
            x[ 8] ^= rotl((x[11]+x[10]), 9);
            x[ 9] ^= rotl((x[ 8]+x[11]),13);
            x[10] ^= rotl((x[ 9]+x[ 8]),18);
            x[12] ^= rotl((x[15]+x[14]), 7);
            x[13] ^= rotl((x[12]+x[15]), 9);
            x[14] ^= rotl((x[13]+x[12]),13);
            x[15] ^= rotl((x[14]+x[13]),18);
        }
        
        for (i = 0; i < stateSize; i++)
        {
            x[i] += input[i];
        }
        
        return intToByteLittle(x);
    }
    
    /**
     * 32 bit word to 4 byte array in little endian order
     *
     * @param   x   value to 'unpack'
     *
     * @return  value of x expressed as a byte[] array in little endian order
     */
    private byte[] intToByteLittle(int x)
    {
        byte[] out = new byte[4];
        out[0] = (byte)x;
        out[1] = (byte)(x >>> 8);
        out[2] = (byte)(x >>> 16);
        out[3] = (byte)(x >>> 24);
        return out;
    }
    
    /**
     * Applies intToByteLittle() over an array of ints, returning a single byte array
     *
     * @param   x   array of values to 'unpack'
     *
     * @return  byte[] array of the values in x
     */
    private byte[] intToByteLittle(int[] x)
    {
        byte[] out = new byte[4*x.length];
        for (int i = 0, j = 0; i < x.length; i++,j+=4)
        {
            System.arraycopy(intToByteLittle(x[i]), 0, out, j, 4);
        }
        return out;
    }
    
    /**
     * Rotate left
     *
     * @param   x   value to rotate
     * @param   y   amount to rotate x
     *
     * @return  rotated x
     */
    private int rotl(int x, int y)
    {
        return (x << y) | (x >>> (32-y));
    }
    
    /**
     * Pack byte[] array into an int in little endian order
     *
     * @param   x       byte array to 'pack'
     * @param   offset  only x[offset]..x[offset+3] will be packed
     *
     * @return  x[offset]..x[offset+3] 'packed' into an int in little-endian order
     */
    private int byteToIntLittle(byte[] x, int offset)
    {
        return ((x[offset++] & 255)) |
               ((x[offset++] & 255) <<  8) |
               ((x[offset++] & 255) << 16) |
               (x[offset  ] << 24);
    }

    private void resetCounter()
    {
        cW0 = 0;
        cW1 = 0;
        cW2 = 0;
    }

    private boolean limitExceeded()
    {
        cW0++;
        if (cW0 == 0)
        {
            cW1++;
            if (cW1 == 0)
            {
                cW2++;
                return (cW2 & 0x20) != 0;          // 2^(32 + 32 + 6)
            }
        }

        return false;
    }
}
