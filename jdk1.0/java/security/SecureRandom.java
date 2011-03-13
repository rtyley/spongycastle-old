package java.security;

import org.spongycastle.crypto.digests.SHA1Digest;

/**
 * An implementation of SecureRandom specifically for the
 * light-weight API, JDK 1.0, and the J2ME. Random generation is 
 * based on the traditional SHA1 with counter. Calling setSeed
 * will always increase the entropy of the hash.
 */
public class SecureRandom
    extends java.util.Random
{
    private static  SecureRandom rand = new SecureRandom();

    private byte[] seed;

    private long        counter = 1;
    private SHA1Digest  digest = new SHA1Digest();
    private byte[]      state = new byte[digest.getDigestSize()];

    // public constructors
    public SecureRandom()
    {
        super(0);
        setSeed(System.currentTimeMillis());
    }

    public SecureRandom(
        byte[] inSeed)
    {
        super(0);
        setSeed(inSeed);
    }

    // protected constructors
    // protected SecureRandom(SecureRandomSpi srs, Provider provider);

    // public class methods
    public static SecureRandom getInstance(String algorithm)
    {
        return new SecureRandom();
    }

    public static SecureRandom getInstance(String algorithm, String provider)
    {
        return new SecureRandom();
    }

    public static byte[] getSeed(
        int numBytes)
    {
        byte[] rv = new byte[numBytes];

        rand.setSeed(System.currentTimeMillis());
        rand.nextBytes(rv);

        return rv;
    }

    // public instance methods
    public byte[] generateSeed(
        int numBytes)
    {
        byte[] rv = new byte[numBytes];
    
        nextBytes(rv);    

        return rv;
    }

    // public final Provider getProvider();
    public void setSeed(
        byte[] inSeed)
    {
        digest.update(inSeed, 0, inSeed.length);
    }
        
    // public methods overriding random
    public void nextBytes(
        byte[] bytes)
    {
        int     stateOff = 0;

        digest.doFinal(state, 0);

        for (int i = 0; i != bytes.length; i++)
        {
            if (stateOff == state.length)
            {
                byte[]  b = longToBytes(counter++);

                digest.update(b, 0, b.length);
                digest.update(state, 0, state.length);
                digest.doFinal(state, 0);
                stateOff = 0;
            }
            bytes[i] = state[stateOff++];
        }

        byte[]  b = longToBytes(counter++);

        digest.update(b, 0, b.length);
        digest.update(state, 0, state.length);
    }

    public void setSeed(
        long rSeed)
    {
        if (rSeed != 0)
        {
            setSeed(longToBytes(rSeed));
        }
    }

    private byte[]  intBytes = new byte[4];

    public int nextInt()
    {
        nextBytes(intBytes);

        int result = 0;

        for (int i = 0; i < 4; i++)
        {
            result = (result << 8) + (intBytes[i] & 0xff);
        }

        return result;
    }

    protected final int next(
        int numBits)
    {
        int     size = (numBits + 7) / 8;
        byte[]  bytes = new byte[size];

        nextBytes(bytes);

        int result = 0;

        for (int i = 0; i < size; i++)
        {
            result = (result << 8) + (bytes[i] & 0xff);
        }

        return result & ((1 << numBits) - 1);
    }

    private byte[]  longBytes = new byte[8];

    private byte[] longToBytes(
        long    val)
    {
        for (int i = 0; i != 8; i++)
        {
            longBytes[i] = (byte)val;
            val >>>= 8;
        }

        return longBytes;
    }
}

