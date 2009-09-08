package org.bouncycastle.crypto.util;

public abstract class Pack
{
    public static int bigEndianToInt(byte[] bs, int off)
    {
        int n = bs[off++] << 24;
        n |= (bs[off++] & 0xff) << 16;
        n |= (bs[off++] & 0xff) << 8;
        n |= (bs[off++] & 0xff);
        return n;
    }

    public static void intToBigEndian(int n, byte[] bs, int off)
    {
        bs[off++] = (byte)(n >>> 24);
        bs[off++] = (byte)(n >>> 16);
        bs[off++] = (byte)(n >>>  8);
        bs[off  ] = (byte)(n       );
    }
}
