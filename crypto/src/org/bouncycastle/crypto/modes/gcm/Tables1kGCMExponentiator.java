package org.bouncycastle.crypto.modes.gcm;

import java.util.ArrayList;

import org.bouncycastle.util.Arrays;

public class Tables1kGCMExponentiator implements GCMExponentiator
{
    // A lookup table of the power-of-two powers of 'x'
    // - lookupPowX2[i] = x^(2^i)
    private ArrayList lookupPowX2;

    public void init(byte[] x)
    {
        if (lookupPowX2 != null && Arrays.areEqual(x, (byte[])lookupPowX2.get(0)))
        {
            return;
        }

        lookupPowX2 = new ArrayList(8);
        lookupPowX2.add(Arrays.clone(x));
    }

    public void exponentiateX(long pow, byte[] output)
    {
        byte[] y = GCMUtil.oneAsBytes();
        if (pow > 0)
        {
            int bit = 0;
            ensureAvailable(63 - numberOfLeadingZeros(pow));

            do
            {
                if ((pow & 1L) != 0)
                {
                    GCMUtil.multiply(y, (byte[])lookupPowX2.get(bit));
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
        int count = lookupPowX2.size();
        if (count <= bit)
        {
            byte[] tmp = (byte[])lookupPowX2.get(count - 1);
            do
            {
                tmp = Arrays.clone(tmp);
                GCMUtil.multiply(tmp, tmp);
                lookupPowX2.add(tmp);
            }
            while (++count <= bit);
        }
    }

    private int numberOfLeadingZeros(long v)
    {
        if (v == 0)
        {
            return 64;
        }
        int n = 1;
        int x = (int)(v >>> 32);
        if (x == 0)
        {
            n += 32;
            x = (int)v;
        }
        if (x >>> 16 == 0)
        {
            n += 16;
            x <<= 16;
        }
        if (x >>> 24 == 0)
        {
            n += 8;
            x <<= 8;
        }
        if (x >>> 28 == 0)
        {
            n += 4;
            x <<= 4;
        }
        if (x >>> 30 == 0)
        {
            n += 2;
            x <<= 2;
        }
        n -= x >>> 31;
        return n;
    }
}
