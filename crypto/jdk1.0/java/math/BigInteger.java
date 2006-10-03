package java.math;

import java.util.Random;
import java.util.Stack;

public class BigInteger
{

    private int sign; // -1 means -ve; +1 means +ve; 0 means 0;
    private int[] magnitude; // array of ints with [0] being the most significant
    private int nBits = -1; // cache bitCount() value
    private int nBitLength = -1; // cache bitLength() value
    private static final long IMASK = 0xffffffffL;
    private long mQuote = -1L; // -m^(-1) mod b, b = 2^32 (see Montgomery mult.)
    
    private BigInteger()
    {
    }

    private BigInteger(int signum, int[] mag)
    {
        sign = signum;
        if (mag.length > 0)
        {
            int i = 0;
            while (i < mag.length && mag[i] == 0)
            {
                i++;
            }
            if (i == 0)
            {
                magnitude = mag;
            }
            else
            {
                // strip leading 0 bytes
                int[] newMag = new int[mag.length - i];
                System.arraycopy(mag, i, newMag, 0, newMag.length);
                magnitude = newMag;
                if (newMag.length == 0)
                    sign = 0;
            }
        }
        else
        {
            magnitude = mag;
            sign = 0;
        }
    }

    public BigInteger(String sval) throws NumberFormatException
    {
        this(sval, 10);
    }

    public BigInteger(String sval, int rdx) throws NumberFormatException
    {
        if (sval.length() == 0)
        {
            throw new NumberFormatException("Zero length BigInteger");
        }

        if (rdx < Character.MIN_RADIX || rdx > Character.MAX_RADIX)
        {
            throw new NumberFormatException("Radix out of range");
        }

        int index = 0;
        sign = 1;

        if (sval.charAt(0) == '-')
        {
            if (sval.length() == 1)
            {
                throw new NumberFormatException("Zero length BigInteger");
            }

            sign = -1;
            index = 1;
        }

        // strip leading zeros from the string value
        while (index < sval.length() && Character.digit(sval.charAt(index), rdx) == 0)
        {
            index++;
        }

        if (index >= sval.length())
        {
            // zero value - we're done
            sign = 0;
            magnitude = new int[0];
            return;
        }

        //////
        // could we work out the max number of ints required to store
        // sval.length digits in the given base, then allocate that
        // storage in one hit?, then generate the magnitude in one hit too?
        //////

        BigInteger b = BigInteger.ZERO;
        BigInteger r = valueOf(rdx);
        while (index < sval.length())
        {
            // (optimise this by taking chunks of digits instead?)
            b = b.multiply(r).add(valueOf(Character.digit(sval.charAt(index), rdx)));
            index++;
        }

        magnitude = b.magnitude;
        return;
    }

    public BigInteger(byte[] bval) throws NumberFormatException
    {
        if (bval.length == 0)
        {
            throw new NumberFormatException("Zero length BigInteger");
        }

        sign = 1;
        if (bval[0] < 0)
        {
            sign = -1;
        }
        magnitude = makeMagnitude(bval, sign);
        if (magnitude.length == 0) {
            sign = 0;
        }
    }

    /**
     * If sign >= 0, packs bytes into an array of ints, most significant first
     * If sign <  0, packs 2's complement of bytes into 
     * an array of ints, most significant first,
     * adding an extra most significant byte in case bval = {0x80, 0x00, ..., 0x00}
     *
     * @param bval
     * @param sign
     * @return
     */
    private int[] makeMagnitude(byte[] bval, int sign)
    {
        if (sign >= 0) {
            int i;
            int[] mag;
            int firstSignificant;

            // strip leading zeros
            for (firstSignificant = 0; firstSignificant < bval.length
                    && bval[firstSignificant] == 0; firstSignificant++);

            if (firstSignificant >= bval.length)
            {
                return new int[0];
            }

            int nInts = (bval.length - firstSignificant + 3) / 4;
            int bCount = (bval.length - firstSignificant) % 4;            
            if (bCount == 0)
                bCount = 4;
            // n = k * (n / k) + n % k
            // bval.length - firstSignificant + 3 = 4 * nInts + bCount - 1
            // bval.length - firstSignificant + 4 - bCount = 4 * nInts

            mag = new int[nInts];
            int v = 0;
            int magnitudeIndex = 0;
            for (i = firstSignificant; i < bval.length; i++)
            {
                // bval.length + 4 - bCount - i + 4 * magnitudeIndex = 4 * nInts
                // 1 <= bCount <= 4
                v <<= 8;
                v |= bval[i] & 0xff;
                bCount--;
                if (bCount <= 0)
                {
                    mag[magnitudeIndex] = v;
                    magnitudeIndex++;
                    bCount = 4;
                    v = 0;
                }
            }
            // 4 - bCount + 4 * magnitudeIndex = 4 * nInts
            // bCount = 4 * (1 + magnitudeIndex - nInts)
            // 1 <= bCount <= 4
            // So bCount = 4 and magnitudeIndex = nInts = mag.length

//            if (magnitudeIndex < mag.length)
//            {
//                mag[magnitudeIndex] = v;
//            }
            return mag;
        }
        else {
            int i;
            int[] mag;
            int firstSignificant;
            

            // strip leading -1's
            for (firstSignificant = 0; firstSignificant < bval.length - 1
                    && bval[firstSignificant] == 0xff; firstSignificant++);

            int nBytes = bval.length;
            boolean leadingByte = false;

            // check for -2^(n-1)
            if (bval[firstSignificant] == 0x80) {
                for (i = firstSignificant + 1; i < bval.length; i++) {
                    if (bval[i] != 0) {
                        break;
                    }
                }
                if (i == bval.length) {
                    nBytes++;
                    leadingByte = true;
                }
            }

            int nInts = (nBytes - firstSignificant + 3) / 4;
            int bCount = (nBytes - firstSignificant) % 4;
            if (bCount == 0)
                bCount = 4;

            // n = k * (n / k) + n % k
            // nBytes - firstSignificant + 3 = 4 * nInts + bCount - 1
            // nBytes - firstSignificant + 4 - bCount = 4 * nInts
            // 1 <= bCount <= 4

            mag = new int[nInts];
            int v = 0;
            int magnitudeIndex = 0;
            // nBytes + 4 - bCount - i + 4 * magnitudeIndex = 4 * nInts
            // 1 <= bCount <= 4
            if (leadingByte) {
                // bval.length + 1 + 4 - bCount - i + 4 * magnitudeIndex = 4 * nInts
                bCount--;
                // bval.length + 1 + 4 - (bCount + 1) - i + 4 * magnitudeIndex = 4 * nInts
                // bval.length + 4 - bCount - i + 4 * magnitudeIndex = 4 * nInts
                if (bCount <= 0)
                {
                    magnitudeIndex++;
                    bCount = 4;
                }
                // bval.length + 4 - bCount - i + 4 * magnitudeIndex = 4 * nInts
                // 1 <= bCount <= 4
            }
            for (i = firstSignificant; i < bval.length; i++)
            {
                // bval.length + 4 - bCount - i + 4 * magnitudeIndex = 4 * nInts
                // 1 <= bCount <= 4
                v <<= 8;
                v |= ~bval[i] & 0xff;
                bCount--;
                if (bCount <= 0)
                {
                    mag[magnitudeIndex] = v;
                    magnitudeIndex++;
                    bCount = 4;
                    v = 0;
                }
            }
            // 4 - bCount + 4 * magnitudeIndex = 4 * nInts
            // 1 <= bCount <= 4
            // bCount = 4 * (1 + magnitudeIndex - nInts)
            // 1 <= bCount <= 4
            // So bCount = 4 and magnitudeIndex = nInts = mag.length

//            if (magnitudeIndex < mag.length)
//            {
//                mag[magnitudeIndex] = v;
//            }
            return inc(mag);
        }

    }

    public BigInteger(int sign, byte[] mag) throws NumberFormatException
    {
        if (sign < -1 || sign > 1)
        {
            throw new NumberFormatException("Invalid sign value");
        }

        if (sign == 0)
        {
            this.sign = 0;
            this.magnitude = new int[0];
            return;
        }

        // copy bytes
        this.magnitude = makeMagnitude(mag, 1);
        this.sign = sign;
    }

    public BigInteger(int numBits, Random rnd) throws IllegalArgumentException
    {
        if (numBits < 0)
        {
            throw new IllegalArgumentException("numBits must be non-negative");
        }

        int nBytes = (numBits + 7) / 8;

        byte[] b = new byte[nBytes];

        if (nBytes > 0)
        {
            nextRndBytes(rnd, b);
            // strip off any excess bits in the MSB
            b[0] &= rndMask[8 * nBytes - numBits];
        }

        this.magnitude = makeMagnitude(b, 1);
        this.sign = 1;
        this.nBits = -1;
        this.nBitLength = -1;
    }

    private static final int BITS_PER_BYTE = 8;
    private static final int BYTES_PER_INT = 4;

    /**
     * strictly speaking this is a little dodgey from a compliance
     * point of view as it forces people to be using SecureRandom as
     * well, that being said - this implementation is for a crypto
     * library and you do have the source!
     */
    private void nextRndBytes(Random rnd, byte[] bytes)
    {
        int numRequested = bytes.length;
        int numGot = 0, 
        r = 0;

        if (rnd instanceof java.security.SecureRandom)
        {
            ((java.security.SecureRandom)rnd).nextBytes(bytes);
        }
        else
        {
            for (; ; )
            {
                for (int i = 0; i < BYTES_PER_INT; i++)
                {
                    if (numGot == numRequested)
                    {
                        return;
                    }

                    r = (i == 0 ? rnd.nextInt() : r >> BITS_PER_BYTE);
                    bytes[numGot++] = (byte)r;
                }
            }
        }
    }

    private static final byte[] rndMask = {(byte)255, 127, 63, 31, 15, 7, 3, 1};

    public BigInteger(int bitLength, int certainty, Random rnd) throws ArithmeticException
    {
        int nBytes = (bitLength + 7) / 8;

        byte[] b = new byte[nBytes];

        do
        {
            if (nBytes > 0)
            {
                nextRndBytes(rnd, b);
                // strip off any excess bits in the MSB
                int xBits = 8 * nBytes - bitLength;
                b[0] &= rndMask[xBits];
                b[0] |= (byte)(1 << (7 - xBits));
            }

            this.magnitude = makeMagnitude(b, 1);
            this.sign = 1;
            this.nBits = -1;
            this.nBitLength = -1;
            this.mQuote = -1L;
            
            if (certainty > 0 && bitLength > 2)
            {
                this.magnitude[this.magnitude.length - 1] |= 1;
            }
        } while (this.bitLength() != bitLength || !this.isProbablePrime(certainty));
    }

    public BigInteger abs()
    {
        return (sign >= 0) ? this : this.negate();
    }

    /**
     * return a = a + b - b preserved.
     */
    private int[] add(int[] a, int[] b)
    {
        int tI = a.length - 1;
        int vI = b.length - 1;
        long m = 0;

        while (vI >= 0)
        {
            m += (((long)a[tI]) & IMASK) + (((long)b[vI--]) & IMASK);
            a[tI--] = (int)m;
            m >>>= 32;
        }

        while (tI >= 0 && m != 0)
        {
            m += (((long)a[tI]) & IMASK);
            a[tI--] = (int)m;
            m >>>= 32;
        }

        return a;
    }

    /**
     * return a = a + 1.
     */
    private int[] inc(int[] a)
    {
        int tI = a.length - 1;
        long m = 0;

        m = (((long)a[tI]) & IMASK) + 1L;
        a[tI--] = (int)m;
        m >>>= 32;

        while (tI >= 0 && m != 0)
        {
            m += (((long)a[tI]) & IMASK);
            a[tI--] = (int)m;
            m >>>= 32;
        }

        return a;
    }

    public BigInteger add(BigInteger val) throws ArithmeticException
    {
        if (val.sign == 0 || val.magnitude.length == 0)
            return this;
        if (this.sign == 0 || this.magnitude.length == 0)
            return val;

        if (val.sign < 0)
        {
            if (this.sign > 0)
                return this.subtract(val.negate());
        }
        else
        {
            if (this.sign < 0)
                return val.subtract(this.negate());
        }

        return addToMagnitude(val.magnitude);
    }

    private BigInteger addToMagnitude(
        int[] magToAdd)
    {
        int[] big, small;
        if (this.magnitude.length < magToAdd.length)
        {
            big = magToAdd;
            small = this.magnitude;
        }
        else
        {
            big = this.magnitude;
            small = magToAdd;
        }

        // Conservatively avoid over-allocation when no overflow possible
        int limit = Integer.MAX_VALUE;
        if (big.length == small.length)
            limit -= small[0];

        boolean possibleOverflow = (big[0] ^ (1 << 31)) >= limit;
        int extra = possibleOverflow ? 1 : 0;

        int[] bigCopy = new int[big.length + extra];
        System.arraycopy(big, 0, bigCopy, extra, big.length);

        bigCopy = add(bigCopy, small);

        return new BigInteger(this.sign, bigCopy);
    }

    public int bitCount()
    {
        if (nBits == -1)
        {
            nBits = 0;
            for (int i = 0; i < magnitude.length; i++)
            {
                nBits += bitCounts[magnitude[i] & 0xff];
                nBits += bitCounts[(magnitude[i] >> 8) & 0xff];
                nBits += bitCounts[(magnitude[i] >> 16) & 0xff];
                nBits += bitCounts[(magnitude[i] >> 24) & 0xff];
            }
        }

        return nBits;
    }

    private final static byte[] bitCounts = {0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1,
        2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4,
        4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3,
        4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3, 3, 4, 3, 4, 4, 5,
        3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 1, 2, 2, 3, 2,
        3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3,
        3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6,
        7, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6,
        5, 6, 6, 7, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 4, 5, 5, 6, 5, 6, 6, 7, 5,
        6, 6, 7, 6, 7, 7, 8};

    private int bitLength(int indx, int[] mag)
    {
        int bitLength;

        if (mag.length == 0)
        {
            return 0;
        }
        else
        {
            while (indx != mag.length && mag[indx] == 0)
            {
                indx++;
            }

            if (indx == mag.length)
            {
                return 0;
            }

            // bit length for everything after the first int
            bitLength = 32 * ((mag.length - indx) - 1);

            // and determine bitlength of first int
            bitLength += bitLen(mag[indx]);

            if (sign < 0)
            {
                // Check if magnitude is a power of two
                boolean pow2 = ((bitCounts[mag[indx] & 0xff])
                        + (bitCounts[(mag[indx] >> 8) & 0xff])
                        + (bitCounts[(mag[indx] >> 16) & 0xff]) + (bitCounts[(mag[indx] >> 24) & 0xff])) == 1;

                for (int i = indx + 1; i < mag.length && pow2; i++)
                {
                    pow2 = (mag[i] == 0);
                }

                bitLength -= (pow2 ? 1 : 0);
            }
        }

        return bitLength;
    }

    public int bitLength()
    {
        if (nBitLength == -1)
        {
            if (sign == 0)
            {
                nBitLength = 0;
            }
            else
            {
                nBitLength = bitLength(0, magnitude);
            }
        }

        return nBitLength;
    }

    //
    // bitLen(val) is the number of bits in val.
    //
    static int bitLen(int w)
    {
        // Binary search - decision tree (5 tests, rarely 6)
        return (w < 1 << 15 ? (w < 1 << 7
                ? (w < 1 << 3 ? (w < 1 << 1
                        ? (w < 1 << 0 ? (w < 0 ? 32 : 0) : 1)
                        : (w < 1 << 2 ? 2 : 3)) : (w < 1 << 5
                        ? (w < 1 << 4 ? 4 : 5)
                        : (w < 1 << 6 ? 6 : 7)))
                : (w < 1 << 11
                        ? (w < 1 << 9 ? (w < 1 << 8 ? 8 : 9) : (w < 1 << 10 ? 10 : 11))
                        : (w < 1 << 13 ? (w < 1 << 12 ? 12 : 13) : (w < 1 << 14 ? 14 : 15)))) : (w < 1 << 23 ? (w < 1 << 19
                ? (w < 1 << 17 ? (w < 1 << 16 ? 16 : 17) : (w < 1 << 18 ? 18 : 19))
                : (w < 1 << 21 ? (w < 1 << 20 ? 20 : 21) : (w < 1 << 22 ? 22 : 23))) : (w < 1 << 27
                ? (w < 1 << 25 ? (w < 1 << 24 ? 24 : 25) : (w < 1 << 26 ? 26 : 27))
                : (w < 1 << 29 ? (w < 1 << 28 ? 28 : 29) : (w < 1 << 30 ? 30 : 31)))));
    }

    public int compareTo(Object o)
    {
        return compareTo((BigInteger)o);
    }

    /**
     * unsigned comparison on two arrays - note the arrays may
     * start with leading zeros.
     */
    private int compareTo(int xIndx, int[] x, int yIndx, int[] y)
    {
        while (xIndx != x.length && x[xIndx] == 0)
        {
            xIndx++;
        }

        while (yIndx != y.length && y[yIndx] == 0)
        {
            yIndx++;
        }

        if ((x.length - xIndx) < (y.length - yIndx))
        {
            return -1;
        }

        if ((x.length - xIndx) > (y.length - yIndx))
        {
            return 1;
        }

        // lengths of magnitudes the same, test the magnitude values

        while (xIndx < x.length)
        {
            long v1 = (long)(x[xIndx++]) & IMASK;
            long v2 = (long)(y[yIndx++]) & IMASK;
            if (v1 < v2)
            {
                return -1;
            }
            if (v1 > v2)
            {
                return 1;
            }
        }

        return 0;
    }

    public int compareTo(BigInteger val)
    {
        if (sign < val.sign)
            return -1;
        if (sign > val.sign)
            return 1;
        if (sign == 0)
            return 0;

        return sign * compareTo(0, magnitude, 0, val.magnitude);
    }

    /**
     * return z = x / y - done in place (z value preserved, x contains the
     * remainder)
     */
    private int[] divide(int[] x, int[] y)
    {
        int xyCmp = compareTo(0, x, 0, y);
        int[] count;

        if (xyCmp > 0)
        {
            int[] c;

            int shift = bitLength(0, x) - bitLength(0, y);

            if (shift > 1)
            {
                c = shiftLeft(y, shift - 1);
                count = shiftLeft(ONE.magnitude, shift - 1);
                if (shift % 32 == 0)
                {
                    // Special case where the shift is the size of an int.
                    int countSpecial[] = new int[shift / 32 + 1];
                    System.arraycopy(count, 0, countSpecial, 1, countSpecial.length - 1);
                    countSpecial[0] = 0;
                    count = countSpecial;
                }
            }
            else
            {
                c = new int[x.length];
                count = new int[1];

                System.arraycopy(y, 0, c, c.length - y.length, y.length);
                count[0] = 1;
            }

            int[] iCount = new int[count.length];

            subtract(0, x, 0, c);
            System.arraycopy(count, 0, iCount, 0, count.length);

            int xStart = 0;
            int cStart = 0;
            int iCountStart = 0;

            for (; ; )
            {
                int cmp = compareTo(xStart, x, cStart, c);

                while (cmp >= 0)
                {
                    subtract(xStart, x, cStart, c);
                    add(count, iCount);
                    cmp = compareTo(xStart, x, cStart, c);
                }

                xyCmp = compareTo(xStart, x, 0, y);

                if (xyCmp > 0)
                {
                    if (x[xStart] == 0)
                    {
                        xStart++;
                    }

                    shift = bitLength(cStart, c) - bitLength(xStart, x);

                    if (shift == 0)
                    {
                        c = shiftRightOne(cStart, c);
                        iCount = shiftRightOne(iCountStart, iCount);
                    }
                    else
                    {
                        c = shiftRight(cStart, c, shift);
                        iCount = shiftRight(iCountStart, iCount, shift);
                    }

                    if (c[cStart] == 0)
                    {
                        cStart++;
                    }

                    if (iCount[iCountStart] == 0)
                    {
                        iCountStart++;
                    }
                }
                else if (xyCmp == 0)
                {
                    add(count, ONE.magnitude);
                    for (int i = xStart; i != x.length; i++)
                    {
                        x[i] = 0;
                    }
                    break;
                }
                else
                {
                    break;
                }
            }
        }
        else if (xyCmp == 0)
        {
            count = new int[1];

            count[0] = 1;
        }
        else
        {
            count = new int[1];

            count[0] = 0;
        }

        return count;
    }

    public BigInteger divide(BigInteger val) throws ArithmeticException
    {
        if (val.sign == 0)
        {
            throw new ArithmeticException("Divide by zero");
        }

        if (sign == 0)
        {
            return BigInteger.ZERO;
        }

        if (val.compareTo(BigInteger.ONE) == 0)
        {
            return this;
        }

        int[] mag = new int[this.magnitude.length];
        System.arraycopy(this.magnitude, 0, mag, 0, mag.length);

        return new BigInteger(this.sign * val.sign, divide(mag, val.magnitude));
    }

    public BigInteger[] divideAndRemainder(BigInteger val) throws ArithmeticException
    {
        if (val.sign == 0)
        {
            throw new ArithmeticException("Divide by zero");
        }

        BigInteger biggies[] = new BigInteger[2];

        if (sign == 0)
        {
            biggies[0] = biggies[1] = BigInteger.ZERO;

            return biggies;
        }

        if (val.compareTo(BigInteger.ONE) == 0)
        {
            biggies[0] = this;
            biggies[1] = BigInteger.ZERO;

            return biggies;
        }

        int[] remainder = new int[this.magnitude.length];
        System.arraycopy(this.magnitude, 0, remainder, 0, remainder.length);

        int[] quotient = divide(remainder, val.magnitude);

        biggies[0] = new BigInteger(this.sign * val.sign, quotient);
        biggies[1] = new BigInteger(this.sign, remainder);

        return biggies;
    }

    public boolean equals(Object val)
    {
        if (val == this)
            return true;

        if (!(val instanceof BigInteger))
            return false;
        BigInteger biggie = (BigInteger)val;

        if (biggie.sign != sign || biggie.magnitude.length != magnitude.length)
            return false;

        for (int i = 0; i < magnitude.length; i++)
        {
            if (biggie.magnitude[i] != magnitude[i])
                return false;
        }

        return true;
    }

    public BigInteger gcd(BigInteger val)
    {
        if (val.sign == 0)
            return this.abs();
        else if (sign == 0)
            return val.abs();

        BigInteger r;
        BigInteger u = this;
        BigInteger v = val;

        while (v.sign != 0)
        {
            r = u.mod(v);
            u = v;
            v = r;
        }

        return u;
    }

    public int hashCode()
    {
        int hc = magnitude.length;

        if (magnitude.length > 0)
        {
            hc ^= magnitude[0];

            if (magnitude.length > 1)
            {
                hc ^= magnitude[magnitude.length - 1];
            }
        }

        return sign < 0 ? ~hc : hc;
    }

    public int intValue()
    {
        if (magnitude.length == 0)
        {
            return 0;
        }

        if (sign < 0)
        {
            return -magnitude[magnitude.length - 1];
        }
        else
        {
            return magnitude[magnitude.length - 1];
        }
    }

    /**
     * return whether or not a BigInteger is probably prime with a
     * probability of 1 - (1/2)**certainty.
     * <p>
     * From Knuth Vol 2, pg 395.
     */
    public boolean isProbablePrime(int certainty)
    {
        if (certainty <= 0)
            return true;

        if (sign == 0)
            return false;

        BigInteger n = this.abs();

        if (!n.testBit(0))
            return n.equals(TWO);

        if (n.equals(ONE))
            return false;

        int test = n.remainder(smallPrimesProduct);
        for (int index = 0; index < smallPrimes.length; ++index)
        {
            int smallPrime = smallPrimes[index];
            if (test % smallPrime == 0)
                return n.bitLength() <= 5 && n.intValue() == smallPrime;
        }

        //
        // let n = 1 + 2^kq
        //
        BigInteger nMinusOne = n.subtract(ONE);
        BigInteger q = nMinusOne;
        int k = q.getLowestSetBit();
        q = q.shiftRight(k);

        Random rnd = new Random();
        do
        {
            BigInteger x;

            do
            {
                x = new BigInteger(n.bitLength(), rnd);
            }
            // NB: Spec says 0 < x < n, but 1 is trivial
            while (x.compareTo(ONE) <= 0 || x.compareTo(n) >= 0);

            BigInteger y = x.modPow(q, n);

            if (!y.equals(ONE))
            {
                // check already = x.ModPow(q << 0, n)
                int r = 0;
                while (!y.equals(nMinusOne))
                {
                    if (++r == k)
                        return false;

                    // check becomes a.ModPow(q << r, n)
                    y = y.modPow(TWO, n);
                }
            }

            certainty -= 2; // composites pass for only 1/4 possible 'x'
        }
        while (certainty > 0);

        return true;
    }

    public long longValue()
    {
        long val = 0;

        if (magnitude.length == 0)
        {
            return 0;
        }

        if (magnitude.length > 1)
        {
            val = ((long)magnitude[magnitude.length - 2] << 32)
                    | (magnitude[magnitude.length - 1] & IMASK);
        }
        else
        {
            val = (magnitude[magnitude.length - 1] & IMASK);
        }

        if (sign < 0)
        {
            return -val;
        }
        else
        {
            return val;
        }
    }

    public BigInteger max(BigInteger val)
    {
        return (compareTo(val) > 0) ? this : val;
    }

    public BigInteger min(BigInteger val)
    {
        return (compareTo(val) < 0) ? this : val;
    }

    public BigInteger mod(BigInteger m) throws ArithmeticException
    {
        if (m.sign <= 0)
        {
            throw new ArithmeticException("BigInteger: modulus is not positive");
        }

        BigInteger biggie = this.remainder(m);

        return (biggie.sign >= 0 ? biggie : biggie.add(m));
    }

    public BigInteger modInverse(BigInteger m) throws ArithmeticException
    {
        if (m.sign != 1)
        {
            throw new ArithmeticException("Modulus must be positive");
        }

        BigInteger x = new BigInteger();
        BigInteger y = new BigInteger();

        BigInteger gcd = BigInteger.extEuclid(this, m, x, y);

        if (!gcd.equals(BigInteger.ONE))
        {
            throw new ArithmeticException("Numbers not relatively prime.");
        }

        if (x.compareTo(BigInteger.ZERO) < 0)
        {
            x = x.add(m);
        }

        return x;
    }

    /**
     * Calculate the numbers u1, u2, and u3 such that:
     *
     * u1 * a + u2 * b = u3
     *
     * where u3 is the greatest common divider of a and b.
     * a and b using the extended Euclid algorithm (refer p. 323
     * of The Art of Computer Programming vol 2, 2nd ed).
     * This also seems to have the side effect of calculating
     * some form of multiplicative inverse.
     *
     * @param a    First number to calculate gcd for
     * @param b    Second number to calculate gcd for
     * @param u1Out      the return object for the u1 value
     * @param u2Out      the return object for the u2 value
     * @return     The greatest common divisor of a and b
     */
    private static BigInteger extEuclid(BigInteger a, BigInteger b, BigInteger u1Out,
            BigInteger u2Out)
    {
        BigInteger res;

        BigInteger u1 = BigInteger.ONE;
        BigInteger u3 = a;
        BigInteger v1 = BigInteger.ZERO;
        BigInteger v3 = b;

        while (v3.compareTo(BigInteger.ZERO) > 0)
        {
            BigInteger q, tn;

            q = u3.divide(v3);

            tn = u1.subtract(v1.multiply(q));
            u1 = v1;
            v1 = tn;

            tn = u3.subtract(v3.multiply(q));
            u3 = v3;
            v3 = tn;
        }

        u1Out.sign = u1.sign;
        u1Out.magnitude = u1.magnitude;

        res = u3.subtract(u1.multiply(a)).divide(b);
        u2Out.sign = res.sign;
        u2Out.magnitude = res.magnitude;

        return u3;
    }

    /**
     * zero out the array x
     */
    private void zero(int[] x)
    {
        for (int i = 0; i != x.length; i++)
        {
            x[i] = 0;
        }
    }

    public BigInteger modPow(BigInteger exponent, BigInteger m) throws ArithmeticException
    {
        if (m.sign < 1)
        {
            throw new ArithmeticException("Modulus must be positive");
        }

        if (m.equals(ONE))
        {
            return ZERO;
        }

        // Zero exponent check
        if (exponent.sign == 0)
        {
            return ONE;
        }

        if (sign == 0)
            return ZERO;

        int[] zVal = null;
        int[] yAccum = null;
        int[] yVal;

        // Montgomery exponentiation is only possible if the modulus is odd,
        // but AFAIK, this is always the case for crypto algo's
        boolean useMonty = ((m.magnitude[m.magnitude.length - 1] & 1) == 1);
        long mQ = 0;
        if (useMonty)
        {
            mQ = m.getMQuote();

            // tmp = this * R mod m
            BigInteger tmp = this.shiftLeft(32 * m.magnitude.length).mod(m);
            zVal = tmp.magnitude;

            useMonty = (zVal.length <= m.magnitude.length);

            if (useMonty)
            {
                yAccum = new int[m.magnitude.length + 1];
                if (zVal.length < m.magnitude.length)
                {
                    int[] longZ = new int[m.magnitude.length];
                    System.arraycopy(zVal, 0, longZ, longZ.length - zVal.length, zVal.length);
                    zVal = longZ;  
                }
            }
        }

        if (!useMonty)
        {
            if (magnitude.length <= m.magnitude.length)
            {
                //zAccum = new int[m.magnitude.length * 2];
                zVal = new int[m.magnitude.length];

                System.arraycopy(magnitude, 0, zVal, zVal.length - magnitude.length,
                        magnitude.length);
            }
            else
            {
                //
                // in normal practice we'll never see this...
                //
                BigInteger tmp = this.remainder(m);

                //zAccum = new int[m.magnitude.length * 2];
                zVal = new int[m.magnitude.length];

                System.arraycopy(tmp.magnitude, 0, zVal, zVal.length - tmp.magnitude.length,
                        tmp.magnitude.length);
            }

            yAccum = new int[m.magnitude.length * 2];
        }

        yVal = new int[m.magnitude.length];

        //
        // from LSW to MSW
        //
        for (int i = 0; i < exponent.magnitude.length; i++)
        {
            int v = exponent.magnitude[i];
            int bits = 0;

            if (i == 0)
            {
                while (v > 0)
                {
                    v <<= 1;
                    bits++;
                }

                //
                // first time in initialise y
                //
                System.arraycopy(zVal, 0, yVal, 0, zVal.length);

                v <<= 1;
                bits++;
            }

            while (v != 0)
            {
                if (useMonty)
                {
                    // Montgomery square algo doesn't exist, and a normal
                    // square followed by a Montgomery reduction proved to
                    // be almost as heavy as a Montgomery mulitply.
                    multiplyMonty(yAccum, yVal, yVal, m.magnitude, mQ);
                }
                else
                {
                    square(yAccum, yVal);
                    remainder(yAccum, m.magnitude);
                    System.arraycopy(yAccum, yAccum.length - yVal.length, yVal, 0, yVal.length);
                    zero(yAccum);
                }
                bits++;

                if (v < 0)
                {
                    if (useMonty)
                    {
                        multiplyMonty(yAccum, yVal, zVal, m.magnitude, mQ);
                    }
                    else
                    {
                        multiply(yAccum, yVal, zVal);
                        remainder(yAccum, m.magnitude);
                        System.arraycopy(yAccum, yAccum.length - yVal.length, yVal, 0,
                                yVal.length);
                        zero(yAccum);
                    }
                }

                v <<= 1;
            }

            while (bits < 32)
            {
                if (useMonty)
                {
                    multiplyMonty(yAccum, yVal, yVal, m.magnitude, mQ);
                }
                else
                {
                    square(yAccum, yVal);
                    remainder(yAccum, m.magnitude);
                    System.arraycopy(yAccum, yAccum.length - yVal.length, yVal, 0, yVal.length);
                    zero(yAccum);
                }
                bits++;
            }
        }

        if (useMonty)
        {
            // Return y * R^(-1) mod m by doing y * 1 * R^(-1) mod m
            zero(zVal);
            zVal[zVal.length - 1] = 1;
            multiplyMonty(yAccum, yVal, zVal, m.magnitude, mQ);
        }

        return new BigInteger(1, yVal);
    }

    /**
     * return w with w = x * x - w is assumed to have enough space.
     */
    private int[] square(int[] w, int[] x)
    {
        long u1, 
        u2, 
        c;

        if (w.length != 2 * x.length)
        {
            throw new IllegalArgumentException("no I don't think so...");
        }

        for (int i = x.length - 1; i != 0; i--)
        {
            long v = (x[i] & IMASK);

            u1 = v * v;
            u2 = u1 >>> 32;
            u1 = u1 & IMASK;

            u1 += (w[2 * i + 1] & IMASK);

            w[2 * i + 1] = (int)u1;
            c = u2 + (u1 >> 32);

            for (int j = i - 1; j >= 0; j--)
            {
                u1 = (x[j] & IMASK) * v;
                u2 = u1 >>> 31; // multiply by 2!
                u1 = (u1 & 0x7fffffff) << 1; // multiply by 2!
                u1 += (w[i + j + 1] & IMASK) + c;

                w[i + j + 1] = (int)u1;
                c = u2 + (u1 >>> 32);
            }
            c += w[i] & IMASK;
            w[i] = (int)c;
            w[i - 1] = (int)(c >> 32);
        }

        u1 = (x[0] & IMASK);
        u1 = u1 * u1;
        u2 = u1 >>> 32;
        u1 = u1 & IMASK;

        u1 += (w[1] & IMASK);

        w[1] = (int)u1;
        w[0] = (int)(u2 + (u1 >> 32) + w[0]);

        return w;
    }

    /**
     * return x with x = y * z - x is assumed to have enough space.
     */
    private int[] multiply(int[] x, int[] y, int[] z)
    {
        for (int i = z.length - 1; i >= 0; i--)
        {
            long a = z[i] & IMASK;
            long value = 0;

            for (int j = y.length - 1; j >= 0; j--)
            {
                value += a * (y[j] & IMASK) + (x[i + j + 1] & IMASK);

                x[i + j + 1] = (int)value;

                value >>>= 32;
            }

            x[i] = (int)value;
        }

        return x;
    }

    private long _extEuclid(long a, long b, long[] uOut)
    {
        long res;

        long u1 = 1;
        long u3 = a;
        long v1 = 0;
        long v3 = b;

        while (v3 > 0)
        {
            long q, tn;

            q = u3 / v3;

            tn = u1 - (v1 * q);
            u1 = v1;
            v1 = tn;

            tn = u3 - (v3 * q);
            u3 = v3;
            v3 = tn;
        }

        uOut[0] = u1;

        res = (u3 - (u1 * a)) / b;
        uOut[1] = res;

        return u3;
    }

    private long _modInverse(long v, long m)
        throws ArithmeticException
    {
        if (m < 0)
        {
            throw new ArithmeticException("Modulus must be positive");
        }

        long[]  x = new long[2];

        long gcd = _extEuclid(v, m, x);

        if (gcd != 1)
        {
            throw new ArithmeticException("Numbers not relatively prime.");
        }

        if (x[0] < 0)
        {
            x[0] = x[0] + m;
        }

        return x[0];
    }

    /**
     * Calculate mQuote = -m^(-1) mod b with b = 2^32 (32 = word size)
     */
    private long getMQuote()
    {
        if (mQuote != -1L)
        { // allready calculated
            return mQuote;
        }
        if ((magnitude[magnitude.length - 1] & 1) == 0)
        {
            return -1L; // not for even numbers
        }

/*
        byte[] bytes = {1, 0, 0, 0, 0};
        BigInteger b = new BigInteger(1, bytes); // 2^32
        mQuote = this.negate().mod(b).modInverse(b).longValue();
*/
        long v = (((~this.magnitude[this.magnitude.length - 1]) | 1) & 0xffffffffL);
        mQuote = _modInverse(v, 0x100000000L);

        return mQuote;
    }

    /**
     * Montgomery multiplication: a = x * y * R^(-1) mod m
     * <br>
     * Based algorithm 14.36 of Handbook of Applied Cryptography.
     * <br>
     * <li> m, x, y should have length n </li>
     * <li> a should have length (n + 1) </li>
     * <li> b = 2^32, R = b^n </li>
     * <br>
     * The result is put in x
     * <br>
     * NOTE: the indices of x, y, m, a different in HAC and in Java
     */
    private void multiplyMonty(int[] a, int[] x, int[] y, int[] m, long mQuote)
    // mQuote = -m^(-1) mod b
    {
        int n = m.length;
        int nMinus1 = n - 1;
        long y_0 = y[n - 1] & IMASK;

        // 1. a = 0 (Notation: a = (a_{n} a_{n-1} ... a_{0})_{b} )
        for (int i = 0; i <= n; i++)
        {
            a[i] = 0;
        }

        // 2. for i from 0 to (n - 1) do the following:
        for (int i = n; i > 0; i--)
        {

            long x_i = x[i - 1] & IMASK;

            // 2.1 u = ((a[0] + (x[i] * y[0]) * mQuote) mod b
            long u = ((((a[n] & IMASK) + ((x_i * y_0) & IMASK)) & IMASK) * mQuote) & IMASK;

            // 2.2 a = (a + x_i * y + u * m) / b
            long prod1 = x_i * y_0;
            long prod2 = u * (m[n - 1] & IMASK);
            long tmp = (a[n] & IMASK) + (prod1 & IMASK) + (prod2 & IMASK);
            long carry = (prod1 >>> 32) + (prod2 >>> 32) + (tmp >>> 32);
            for (int j = nMinus1; j > 0; j--)
            {
                prod1 = x_i * (y[j - 1] & IMASK);
                prod2 = u * (m[j - 1] & IMASK);
                tmp = (a[j] & IMASK) + (prod1 & IMASK) + (prod2 & IMASK) + (carry & IMASK);
                carry = (carry >>> 32) + (prod1 >>> 32) + (prod2 >>> 32) + (tmp >>> 32);
                a[j + 1] = (int)tmp; // division by b
            }
            carry += (a[0] & IMASK);
            a[1] = (int)carry;
            a[0] = (int)(carry >>> 32);
        }

        // 3. if x >= m the x = x - m
        if (compareTo(0, a, 0, m) >= 0)
        {
            subtract(0, a, 0, m);
        }

        // put the result in x
        System.arraycopy(a, 1, x, 0, n);
    }

    public BigInteger multiply(BigInteger val)
    {
        if (sign == 0 || val.sign == 0)
            return BigInteger.ZERO;

        int[] res = new int[magnitude.length + val.magnitude.length];

        return new BigInteger(sign * val.sign, multiply(res, magnitude, val.magnitude));
    }

    public BigInteger negate()
    {
        return new BigInteger( -sign, magnitude);
    }

    public BigInteger not()
    {
        return add(ONE).negate();
    }

    public BigInteger pow(int exp) throws ArithmeticException
    {
        if (exp < 0)
            throw new ArithmeticException("Negative exponent");
        if (sign == 0)
            return (exp == 0 ? BigInteger.ONE : this);

        BigInteger y, 
        z;
        y = BigInteger.ONE;
        z = this;

        while (exp != 0)
        {
            if ((exp & 0x1) == 1)
            {
                y = y.multiply(z);
            }
            exp >>= 1;
            if (exp != 0)
            {
                z = z.multiply(z);
            }
        }

        return y;
    }

    private int remainder(int m)
    {
        long acc = 0;
        for (int pos = 0; pos < magnitude.length; ++pos)
        {
            acc = (acc << 32 | ((long)magnitude[pos] & 0xffffffffL)) % m;
        }

        return (int) acc;
    }
    
    /**
     * return x = x % y - done in place (y value preserved)
     */
    private int[] remainder(int[] x, int[] y)
    {
        int xyCmp = compareTo(0, x, 0, y);

        if (xyCmp > 0)
        {
            int[] c;
            int shift = bitLength(0, x) - bitLength(0, y);

            if (shift > 1)
            {
                c = shiftLeft(y, shift - 1);
            }
            else
            {
                c = new int[x.length];

                System.arraycopy(y, 0, c, c.length - y.length, y.length);
            }

            subtract(0, x, 0, c);

            int xStart = 0;
            int cStart = 0;

            for (; ; )
            {
                int cmp = compareTo(xStart, x, cStart, c);

                while (cmp >= 0)
                {
                    subtract(xStart, x, cStart, c);
                    cmp = compareTo(xStart, x, cStart, c);
                }

                xyCmp = compareTo(xStart, x, 0, y);

                if (xyCmp > 0)
                {
                    if (x[xStart] == 0)
                    {
                        xStart++;
                    }

                    shift = bitLength(cStart, c) - bitLength(xStart, x);

                    if (shift == 0)
                    {
                        c = shiftRightOne(cStart, c);
                    }
                    else
                    {
                        c = shiftRight(cStart, c, shift);
                    }

                    if (c[cStart] == 0)
                    {
                        cStart++;
                    }
                }
                else if (xyCmp == 0)
                {
                    for (int i = xStart; i != x.length; i++)
                    {
                        x[i] = 0;
                    }
                    break;
                }
                else
                {
                    break;
                }
            }
        }
        else if (xyCmp == 0)
        {
            for (int i = 0; i != x.length; i++)
            {
                x[i] = 0;
            }
        }

        return x;
    }

    public BigInteger remainder(BigInteger val) throws ArithmeticException
    {
        if (val.sign == 0)
        {
            throw new ArithmeticException("BigInteger: Divide by zero");
        }

        if (sign == 0)
        {
            return BigInteger.ZERO;
        }

        int[] res = new int[this.magnitude.length];

        System.arraycopy(this.magnitude, 0, res, 0, res.length);

        return new BigInteger(sign, remainder(res, val.magnitude));
    }

    /**
     * do a left shift - this returns a new array.
     */
    private int[] shiftLeft(int[] mag, int n)
    {
        int nInts = n >>> 5;
        int nBits = n & 0x1f;
        int magLen = mag.length;
        int newMag[] = null;

        if (nBits == 0)
        {
            newMag = new int[magLen + nInts];
            System.arraycopy(mag, 0, newMag, 0, magLen);
        }
        else
        {
            int i = 0;
            int nBits2 = 32 - nBits;
            int highBits = mag[0] >>> nBits2;

            if (highBits != 0)
            {
                newMag = new int[magLen + nInts + 1];
                newMag[i++] = highBits;
            }
            else
            {
                newMag = new int[magLen + nInts];
            }

            int m = mag[0];
            for (int j = 0; j < magLen - 1; j++)
            {
                int next = mag[j + 1];

                newMag[i++] = (m << nBits) | (next >>> nBits2);
                m = next;
            }

            newMag[i] = mag[magLen - 1] << nBits;
        }

        return newMag;
    }

    public BigInteger shiftLeft(int n)
    {
        if (sign == 0 || magnitude.length == 0)
        {
            return ZERO;
        }
        if (n == 0)
        {
            return this;
        }

        if (n < 0)
        {
            return shiftRight( -n);
        }

        return new BigInteger(sign, shiftLeft(magnitude, n));
    }

    /**
     * do a right shift - this does it in place.
     */
    private int[] shiftRight(int start, int[] mag, int n)
    {
        int nInts = (n >>> 5) + start;
        int nBits = n & 0x1f;
        int magLen = mag.length;

        if (nInts != start)
        {
            int delta = (nInts - start);

            for (int i = magLen - 1; i >= nInts; i--)
            {
                mag[i] = mag[i - delta];
            }
            for (int i = nInts - 1; i >= start; i--)
            {
                mag[i] = 0;
            }
        }

        if (nBits != 0)
        {
            int nBits2 = 32 - nBits;
            int m = mag[magLen - 1];

            for (int i = magLen - 1; i >= nInts + 1; i--)
            {
                int next = mag[i - 1];

                mag[i] = (m >>> nBits) | (next << nBits2);
                m = next;
            }

            mag[nInts] >>>= nBits;
        }

        return mag;
    }

    /**
     * do a right shift by one - this does it in place.
     */
    private int[] shiftRightOne(int start, int[] mag)
    {
        int magLen = mag.length;

        int m = mag[magLen - 1];

        for (int i = magLen - 1; i >= start + 1; i--)
        {
            int next = mag[i - 1];

            mag[i] = (m >>> 1) | (next << 31);
            m = next;
        }

        mag[start] >>>= 1;

        return mag;
    }

    public BigInteger shiftRight(int n)
    {
        if (n == 0)
        {
            return this;
        }

        if (n < 0)
        {
            return shiftLeft( -n);
        }

        if (n >= bitLength())
        {
            return (this.sign < 0 ? valueOf( -1) : BigInteger.ZERO);
        }

        int[] res = new int[this.magnitude.length];

        System.arraycopy(this.magnitude, 0, res, 0, res.length);

        return new BigInteger(this.sign, shiftRight(0, res, n));
    }

    public int signum()
    {
        return sign;
    }

    /**
     * returns x = x - y - we assume x is >= y
     */
    private int[] subtract(int xStart, int[] x, int yStart, int[] y)
    {
        int iT = x.length - 1;
        int iV = y.length - 1;
        long m;
        int borrow = 0;

        do
        {
            m = (((long)x[iT]) & IMASK) - (((long)y[iV--]) & IMASK) + borrow;

            x[iT--] = (int)m;

            if (m < 0)
            {
                borrow = -1;
            }
            else
            {
                borrow = 0;
            }
        } while (iV >= yStart);

        while (iT >= xStart)
        {
            m = (((long)x[iT]) & IMASK) + borrow;
            x[iT--] = (int)m;

            if (m < 0)
            {
                borrow = -1;
            }
            else
            {
                break;
            }
        }

        return x;
    }

    public BigInteger subtract(BigInteger val)
    {
        if (val.sign == 0 || val.magnitude.length == 0)
        {
            return this;
        }
        if (sign == 0 || magnitude.length == 0)
        {
            return val.negate();
        }
        if (this.sign != val.sign)
        {
            return this.add(val.negate());
        }

        int compare = compareTo(0, magnitude, 0, val.magnitude);
        if (compare == 0)
        {
            return ZERO;
        }

        BigInteger bigun, littlun;
        if (compare < 0)
        {
            bigun = val;
            littlun = this;
        }
        else
        {
            bigun = this;
            littlun = val;
        }

        int res[] = new int[bigun.magnitude.length];

        System.arraycopy(bigun.magnitude, 0, res, 0, res.length);

        return new BigInteger(this.sign * compare, subtract(0, res, 0, littlun.magnitude));
    }

    public byte[] toByteArray()
    {
        int bitLength = bitLength();
        byte[] bytes = new byte[bitLength / 8 + 1];

        int bytesCopied = 4;
        int mag = 0;
        int ofs = magnitude.length - 1;
        int carry = 1;
        long lMag;
        for (int i = bytes.length - 1; i >= 0; i--)
        {
            if (bytesCopied == 4 && ofs >= 0)
            {
                if (sign < 0)
                {
                    // we are dealing with a +ve number and we want a -ve one, so
                    // invert the magnitude ints and add 1 (propagating the carry)
                    // to make a 2's complement -ve number
                    lMag = ~magnitude[ofs--] & IMASK;
                    lMag += carry;
                    if ((lMag & ~IMASK) != 0)
                        carry = 1;
                    else
                        carry = 0;
                    mag = (int)(lMag & IMASK);
                }
                else
                {
                    mag = magnitude[ofs--];
                }
                bytesCopied = 1;
            }
            else
            {
                mag >>>= 8;
                bytesCopied++;
            }

            bytes[i] = (byte)mag;
        }

        return bytes;
    }

    public BigInteger xor(BigInteger val) 
    {
        if (this.sign == 0)
        {
            return val;
        }

        if (val.sign == 0)
        {
            return this;
        }

        int[] aMag = this.sign > 0
            ? this.magnitude
            : this.add(ONE).magnitude;

        int[] bMag = val.sign > 0
            ? val.magnitude
            : val.add(ONE).magnitude;

        boolean resultNeg = (sign < 0 && val.sign >= 0) || (sign >= 0 && val.sign < 0);
        int resultLength = Math.max(aMag.length, bMag.length);
        int[] resultMag = new int[resultLength];

        int aStart = resultMag.length - aMag.length;
        int bStart = resultMag.length - bMag.length;

        for (int i = 0; i < resultMag.length; ++i)
        {
            int aWord = i >= aStart ? aMag[i - aStart] : 0;
            int bWord = i >= bStart ? bMag[i - bStart] : 0;

            if (this.sign < 0)
            {
                aWord = ~aWord;
            }

            if (val.sign < 0)
            {
                bWord = ~bWord;
            }

            resultMag[i] = aWord ^ bWord;

            if (resultNeg)
            {
                resultMag[i] = ~resultMag[i];
            }
        }

        BigInteger result = new BigInteger(1, resultMag);

        if (resultNeg)
        {
            result = result.not();
        }

        return result;
    }

    public BigInteger or(
        BigInteger value)
    {
        if (this.sign == 0)
        {
            return value;
        }

        if (value.sign == 0)
        {
            return this;
        }

        int[] aMag = this.sign > 0
                        ? this.magnitude
                        : this.add(ONE).magnitude;

        int[] bMag = value.sign > 0
                        ? value.magnitude
                        : value.add(ONE).magnitude;

        boolean resultNeg = sign < 0 || value.sign < 0;
        int resultLength = Math.max(aMag.length, bMag.length);
        int[] resultMag = new int[resultLength];

        int aStart = resultMag.length - aMag.length;
        int bStart = resultMag.length - bMag.length;

        for (int i = 0; i < resultMag.length; ++i)
        {
            int aWord = i >= aStart ? aMag[i - aStart] : 0;
            int bWord = i >= bStart ? bMag[i - bStart] : 0;

            if (this.sign < 0)
            {
                aWord = ~aWord;
            }

            if (value.sign < 0)
            {
                bWord = ~bWord;
            }

            resultMag[i] = aWord | bWord;

            if (resultNeg)
            {
                resultMag[i] = ~resultMag[i];
            }
        }

        BigInteger result = new BigInteger(1, resultMag);

        if (resultNeg)
        {
            result = result.not();
        }

        return result;
    }
    
    public BigInteger setBit(int n) 
        throws ArithmeticException 
    {
        if (n<0)
        {
             throw new ArithmeticException("Bit address less than zero");
        }
         
        int wordNum = n/32;
        int result[];
        
        result = createResult(wordNum);
        
        result[result.length - wordNum - 1] |= 1 << (n % 32);
    
        return new BigInteger(sign, result);
    }
    
    public BigInteger clearBit(int n) 
        throws ArithmeticException 
    {
        if (n<0)
        {
             throw new ArithmeticException("Bit address less than zero");
        }
         
        int wordNum = n/32;
        int result[];
        
        result = createResult(wordNum);
        
        result[result.length - wordNum - 1] &= ~(1 << (n % 32));
    
        return new BigInteger(sign, result);
    }

    public BigInteger flipBit(int n) 
        throws ArithmeticException 
    {
        if (n<0)
        {
             throw new ArithmeticException("Bit address less than zero");
        }
         
        int wordNum = n/32;
        int[] result = createResult(wordNum);
        
        result[result.length - wordNum - 1] ^= (1 << (n % 32));
    
        return new BigInteger(sign, result);
    }

    private int[] createResult(int wordNum)
    {
        int[] result;
        if (magnitude.length < wordNum + 1)
        {
            result = new int[wordNum + 1];
        }
        else
        {
            result = new int[magnitude.length];
        }
        
        System.arraycopy(magnitude, 0, result, result.length - magnitude.length, magnitude.length);
        return result;
    }
        
    public String toString()
    {
        return toString(10);
    }

    public String toString(int rdx)
    {
        if (magnitude == null)
        {
            return "null";
        }
        else if (sign == 0)
        {
            return "0";
        }

        String s = "";
        String h;

        if (rdx == 16)
        {
            for (int i = 0; i < magnitude.length; i++)
            {
                h = "0000000" + Integer.toHexString(magnitude[i]);
                h = h.substring(h.length() - 8);
                s = s + h;
            }
        }
        else
        {
            // This is algorithm 1a from chapter 4.4 in Seminumerical Algorithms, slow but it works
            Stack S = new Stack();
            BigInteger base = new BigInteger(Integer.toString(rdx, rdx), rdx);
            // The sign is handled separatly.
            // Notice however that for this to work, radix 16 _MUST_ be a special case,
            // unless we want to enter a recursion well. In their infinite wisdom, why did not 
            // the Sun engineers made a c'tor for BigIntegers taking a BigInteger as parameter?
            // (Answer: Becuase Sun's BigIntger is clonable, something bouncycastle's isn't.)
            BigInteger u = new BigInteger(this.abs().toString(16), 16);
            BigInteger b;

            // For speed, maye these test should look directly a u.magnitude.length?
            while (!u.equals(BigInteger.ZERO))
            {
                b = u.mod(base);
                if (b.equals(BigInteger.ZERO))
                    S.push("0");
                else
                    S.push(Integer.toString(b.magnitude[0], rdx));
                u = u.divide(base);
            }
            // Then pop the stack
            while (!S.empty())
                s = s + S.pop();
        }
        // Strip leading zeros.
        while (s.length() > 1 && s.charAt(0) == '0')
            s = s.substring(1);

        if (s.length() == 0)
            s = "0";
        else if (sign == -1)
            s = "-" + s;

        return s;
    }

    public static final BigInteger ZERO = new BigInteger(0, new byte[0]);
    public static final BigInteger ONE = valueOf(1);
    private static final BigInteger TWO = valueOf(2);

    private static final int[] smallPrimes = new int[]{ 3, 5, 7, 11, 13, 17, 19, 23 };
    private static final int smallPrimesProduct = 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23;

    public static BigInteger valueOf(long val)
    {
        if (val == 0)
        {
            return BigInteger.ZERO;
        }

        if (val < 0)
        {
            if (val == Long.MIN_VALUE)
            {
                return valueOf(~val).not();
            }

            return valueOf(-val).negate();
        }

        // store val into a byte array
        byte[] b = new byte[8];
        for (int i = 0; i < 8; i++)
        {
            b[7 - i] = (byte)val;
            val >>= 8;
        }

        return new BigInteger(b);
    }

    public int getLowestSetBit()
    {
        if (this.equals(ZERO))
        {
            return -1;
        }

        int w = magnitude.length - 1;

        while (w >= 0)
        {
            if (magnitude[w] != 0)
            {
                break;
            }

            w--;
        }

        int b = 31;

        while (b > 0)
        {
            if ((magnitude[w] << b) == 0x80000000)
            {
                break;
            }

            b--;
        }

        return (((magnitude.length - 1) - w) * 32 + (31 - b));
    }

    public boolean testBit(int n) 
        throws ArithmeticException
    {
        if (n < 0)
        {
            throw new ArithmeticException("Bit position must not be negative");
        }

        if ((n / 32) >= magnitude.length)
        {
            return sign < 0;
        }

        return ((magnitude[(magnitude.length - 1) - n / 32] >> (n % 32)) & 1) > 0;
    }
}
