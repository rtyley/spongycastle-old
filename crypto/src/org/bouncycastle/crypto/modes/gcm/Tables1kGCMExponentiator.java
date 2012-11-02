package org.bouncycastle.crypto.modes.gcm;

import org.bouncycastle.util.Arrays;

public class Tables1kGCMExponentiator implements GCMExponentiator
{
    // A lookup table of the power-of-two powers of 'x'
    // - lookupPowX2[i] = x^(2^i)
    private final byte[][] lookupPowX2 = new byte[64][];

    private int highestIndex = -1;

    public void init(byte[] x)
    {
        if (Arrays.areEqual(x, lookupPowX2[0]))
        {
            return;
        }

        for (int i = 1; i <= highestIndex; ++i)
        {
            lookupPowX2[i] = null;
        }

        lookupPowX2[0] = Arrays.clone(x);
        highestIndex = 0;
    }

    public void exponentiateX(long pow, byte[] output)
    {
        byte[] y = GCMUtil.oneAsBytes();
        if (pow > 0)
        {
            int bit = 0;
            ensureAvailable(63 - Long.numberOfLeadingZeros(pow));

            do
            {
                if ((pow & 1L) != 0)
                {
                    GCMUtil.multiply(y, lookupPowX2[bit]);
                }
                ++bit;
                pow >>>= 1;
            }
            while (pow > 0);
        }

        System.arraycopy(y, 0, output, 0, 16);
    }

    private void ensureAvailable(int bit)
    {
        while (highestIndex < bit)
        {
          byte[] tmp = Arrays.clone(lookupPowX2[highestIndex]);
          GCMUtil.multiply(tmp, tmp);
          lookupPowX2[++highestIndex] = tmp;
        }
    }
}
