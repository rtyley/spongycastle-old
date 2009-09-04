package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/**
 * Implements the Galois/Counter mode (GCM) detailed in
 * NIST Special Publication 800-38D.
 */
public class GCMBlockCipher
    implements AEADBlockCipher
{
    private static final int BLOCK_SIZE = 16;
    private static final byte[] ZEROES = new byte[BLOCK_SIZE];

    private final BlockCipher   cipher;

    // These fields are set by init and not modified by processing
    private boolean             forEncryption;
    private int                 macSize;
    private byte[]              nonce;
    private byte[]              A;
    private KeyParameter        keyParam;
    private byte[]              H;
    private int[][][]           M = new int[16][256][];
    private byte[]              initS;
    private byte[]              J0;

    // These fields are modified during processing
    private byte[]      bufBlock;
    private byte[]      macBlock;
    private byte[]      S;
    private byte[]      counter;
    private int         bufOff;
    private long        totalLength;

    public GCMBlockCipher(BlockCipher c)
    {
        if (c.getBlockSize() != BLOCK_SIZE)
        {
            throw new IllegalArgumentException(
                "cipher required with a block size of " + BLOCK_SIZE + ".");
        }

        this.cipher = c;
    }

    public BlockCipher getUnderlyingCipher()
    {
        return cipher;
    }

    public String getAlgorithmName()
    {
        return cipher.getAlgorithmName() + "/GCM";
    }

    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        this.forEncryption = forEncryption;
        this.macSize = 16; // TODO Make configurable?
        this.macBlock = null;

        // TODO If macSize limitation is removed, be very careful about bufBlock
        int bufLength = forEncryption ? BLOCK_SIZE : (BLOCK_SIZE + macSize); 
        this.bufBlock = new byte[bufLength];

        if (params instanceof AEADParameters)
        {
            AEADParameters param = (AEADParameters)params;

            nonce = param.getNonce();
            A = param.getAssociatedText();
//            macSize = param.getMacSize() / 8;
            if (param.getMacSize() != 128)
            {
                // TODO Make configurable?
                throw new IllegalArgumentException("only 128-bit MAC supported currently");
            }
            keyParam = param.getKey();
        }
        else if (params instanceof ParametersWithIV)
        {
            ParametersWithIV param = (ParametersWithIV)params;

            nonce = param.getIV();
            A = null;
            keyParam = (KeyParameter)param.getParameters();
        }
        else
        {
            throw new IllegalArgumentException("invalid parameters passed to GCM");
        }

        if (nonce == null || nonce.length < 1)
        {
            throw new IllegalArgumentException("IV must be at least 1 byte");
        }

        if (A == null)
        {
            // Avoid lots of null checks
            A = new byte[0];
        }

        // Cipher always used in forward mode
        cipher.init(true, keyParam);

        // TODO This should be configurable by init parameters
        // (but must be 16 if nonce length not 12) (BLOCK_SIZE?)
//        this.tagLength = 16;

        this.H = new byte[BLOCK_SIZE];
        cipher.processBlock(ZEROES, 0, H, 0);
        calculateM();

        this.initS = gHASH(A);

        if (nonce.length == 12)
        {
            this.J0 = new byte[16];
            System.arraycopy(nonce, 0, J0, 0, nonce.length);
            this.J0[15] = 0x01;
        }
        else
        {
            byte[] N = gHASH(nonce);
            byte[] X = new byte[16];
            packLength((long)nonce.length * 8, X, 8);
            xor(N, X);
            this.J0 = multiplyH(N);
        }

        this.S = Arrays.clone(initS);
        this.counter = Arrays.clone(J0);
        this.bufOff = 0;
        this.totalLength = 0;
    }

    public byte[] getMac()
    {
        return Arrays.clone(macBlock);
    }

    public int getOutputSize(int len)
    {
        if (forEncryption)
        {
             return len + bufOff + macSize;
        }

        return len + bufOff - macSize;
    }

    public int getUpdateOutputSize(int len)
    {
        return ((len + bufOff) / BLOCK_SIZE) * BLOCK_SIZE;
    }

    public int processByte(byte in, byte[] out, int outOff)
        throws DataLengthException
    {
        return process(in, out, outOff);
    }

    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
        throws DataLengthException
    {
        int resultLen = 0;

        for (int i = 0; i != len; i++)
        {
//            resultLen += process(in[inOff + i], out, outOff + resultLen);
            bufBlock[bufOff++] = in[inOff + i];

            if (bufOff == bufBlock.length)
            {
                gCTRBlock(bufBlock, BLOCK_SIZE, out, outOff + resultLen);
                if (!forEncryption)
                {
                    System.arraycopy(bufBlock, BLOCK_SIZE, bufBlock, 0, BLOCK_SIZE);
                }
//              bufOff = 0;
                bufOff = bufBlock.length - BLOCK_SIZE;
//              return bufBlock.Length;
                resultLen += BLOCK_SIZE;
            }
        }

        return resultLen;
    }

    private int process(byte in, byte[] out, int outOff)
        throws DataLengthException
    {
        bufBlock[bufOff++] = in;

        if (bufOff == bufBlock.length)
        {
            gCTRBlock(bufBlock, BLOCK_SIZE, out, outOff);
            if (!forEncryption)
            {
                System.arraycopy(bufBlock, BLOCK_SIZE, bufBlock, 0, BLOCK_SIZE);
            }
//            bufOff = 0;
            bufOff = bufBlock.length - BLOCK_SIZE;
//            return bufBlock.length;
            return BLOCK_SIZE;
        }

        return 0;
    }

    public int doFinal(byte[] out, int outOff)
        throws IllegalStateException, InvalidCipherTextException
    {
        int extra = bufOff;
        if (!forEncryption)
        {
            if (extra < macSize)
            {
                throw new InvalidCipherTextException("data too short");
            }
            extra -= macSize;
        }

        if (extra > 0)
        {
            byte[] tmp = new byte[BLOCK_SIZE];
            System.arraycopy(bufBlock, 0, tmp, 0, extra);
            gCTRBlock(tmp, extra, out, outOff);
        }

        // Final gHASH
        byte[] X = new byte[16];
        packLength((long)A.length * 8, X, 0);
        packLength(totalLength * 8, X, 8);

        xor(X, S);
        S = multiplyH(X);

        // TODO Fix this if tagLength becomes configurable
        // T = MSBt(GCTRk(J0,S))
        byte[] tag = new byte[BLOCK_SIZE];
        cipher.processBlock(J0, 0, tag, 0);
        xor(tag, S);

        int resultLen = extra;

        if (forEncryption)
        {
            this.macBlock = tag;
            System.arraycopy(tag, 0, out, outOff + bufOff, tag.length);
            resultLen += tag.length;
        }
        else
        {
            this.macBlock = new byte[macSize];
            System.arraycopy(bufBlock, extra, macBlock, 0, macSize);
            if (!Arrays.areEqual(tag, this.macBlock))
            {
                throw new InvalidCipherTextException("mac check in GCM failed");
            }
        }

        reset(false);

        return resultLen;
    }

    public void reset()
    {
        reset(true);
    }

    private void reset(
        boolean clearMac)
    {
        S = Arrays.clone(initS);
        counter = Arrays.clone(J0);
        bufOff = 0;
        totalLength = 0;

        if (bufBlock != null)
        {
            Arrays.fill(bufBlock, (byte)0);
        }

        if (clearMac)
        {
            macBlock = null;
        }

        cipher.reset();
    }

    private void gCTRBlock(byte[] buf, int bufCount, byte[] out, int outOff)
    {
        inc(counter);

        byte[] tmp = new byte[BLOCK_SIZE];
        cipher.processBlock(counter, 0, tmp, 0);

        byte[] hashBytes;
        if (forEncryption)
        {
            System.arraycopy(ZEROES, bufCount, tmp, bufCount, BLOCK_SIZE - bufCount);
            hashBytes = tmp;
        }
        else
        {
            hashBytes = buf;
        }

        for (int i = bufCount - 1; i >= 0; --i)
        {
            tmp[i] ^= buf[i];
            out[outOff + i] = tmp[i];
        }

//        gHASHBlock(hashBytes);
        xor(S, hashBytes);
        S = multiplyH(S);

        totalLength += bufCount;
    }

    private byte[] gHASH(byte[] b)
    {
        byte[] Y = new byte[16];

        for (int pos = 0; pos < b.length; pos += 16)
        {
            byte[] X = new byte[16];
            int num = Math.min(b.length - pos, 16);
            System.arraycopy(b, pos, X, 0, num);
            xor(X, Y);
            Y = multiplyH(X);
        }

        return Y;
    }

//    private void gHASHBlock(byte[] block)
//    {
//        xor(S, block);
//        S = multiplyH(S);
//    }

    private static void inc(byte[] block)
    {
//        assert block.length == 16;

        for (int i = 15; i >= 12; --i)
        {
            byte b = (byte)((block[i] + 1) & 0xff);
            block[i] = b;

            if (b != 0)
            {
                break;
            }
        }
    }

    private static void shiftRight(int[] block)
    {
        int i = 0;
        int bit = 0;
        for (;;)
        {
            int b = block[i];
            block[i] = (b >>> 1) | bit;
            if (++i == 4) break;
            bit = (b & 1) << 31;
        }
    }

    private static void xor(byte[] block, byte[] val)
    {
//      assert block.Length == 16;

        for (int i = 0; i < 16; ++i)
        {
            block[i] ^= val[i];
        }
    }

    private static void xor(int[] block, int[] val)
    {
//      assert block.length == 4 && val.length == 4;

        for (int i = 0; i < 4; ++i)
        {
            block[i] ^= val[i];
        }
    }

    private byte[] multiplyH(byte[] x)
    {
//      assert block.Length == 16;

//      return multiply(x, H);

        int[] z = new int[4];
        for (int i = 0; i != 16; ++i)
        {
            xor(z, M[i][x[i] & 0xff]);
        }
        return asBytes(z);
    }

//    private static byte[] multiply(byte[] x, byte[] y)
//    {
//        BigInteger Y = new BigInteger(1, y);
//        byte[] z = new byte[16];
//        byte[] v = Arrays.clone(x);
//
//        for (int i = 0; i < 128; ++i)
//        {
//            if (Y.testBit(127 - i))
//            {
//                xor(z, v);
//            }
//
//            boolean lsb = (v[15] & 1) == 1;
//            shiftRight(v);
//            if (lsb)
//            {
//                xor(v, R);
//            }
//        }
//
//        return z;
//    }

    // P is the value with only bit i=1 set
    private static void multiplyP(int[] x)
    {
        boolean lsb = (x[3] & 1) == 1;
        shiftRight(x);
        if (lsb)
        {
            // R = new int[]{ 0xe1000000, 0, 0, 0 };
//            xor(v, R);
            x[0] ^= 0xe1000000;
        }
    }

    private static void multiplyP8(int[] x)
    {
        for (int i = 0; i < 8; ++i)
        {
            multiplyP(x);
        }
    }

    private void calculateM()
    {
        M[0][0] = new int[4];
        M[0][128] = asInts(H);
        for (int j = 64; j >= 1; j >>= 1)
        {
            int[] tmp = new int[4];
            System.arraycopy(M[0][j + j], 0, tmp, 0, 4);

            multiplyP(tmp);
            M[0][j] = tmp;
        }
        for (int i = 0;;)
        {
            for (int j = 2; j < 256; j += j)
            {
                for (int k = 1; k < j; ++k)
                {
                    int[] tmp = new int[4];
                    System.arraycopy(M[i][j], 0, tmp, 0, 4);

                    xor(tmp, M[i][k]);
                    M[i][j + k] = tmp;
                }
            }

            if (++i == 16) return;

            M[i][0] = new int[4];
            for (int j = 128; j > 0; j >>= 1)
            {
                int[] tmp = new int[4];
                System.arraycopy(M[i - 1][j], 0, tmp, 0, 4);

                multiplyP8(tmp);
                M[i][j] = tmp;
            }
        }
    }

    private static void packLength(long count, byte[] bs, int off)
    {
        intToBE((int)(count >>> 32), bs, off); 
        intToBE((int)count, bs, off + 4);
    }

    private static void intToBE(int n, byte[] bs, int off)
    {
        bs[off++] = (byte)(n >>> 24);
        bs[off++] = (byte)(n >>> 16);
        bs[off++] = (byte)(n >>>  8);
        bs[off  ] = (byte)(n       );
    }

    private static int BEToInt(byte[] bs, int off)
    {
        int n = bs[off++] << 24;
        n |= (bs[off++] & 0xff) << 16;
        n |= (bs[off++] & 0xff) << 8;
        n |= (bs[off++] & 0xff);
        return n;
    }

    private static byte[] asBytes(int[] us)
    {
        byte[] bs = new byte[16];
        intToBE(us[0], bs, 0);
        intToBE(us[1], bs, 4);
        intToBE(us[2], bs, 8);
        intToBE(us[3], bs, 12);
        return bs;
    }

    private static int[] asInts(byte[] bs)
    {
        int[] us = new int[4];
        us[0] = BEToInt(bs, 0);
        us[1] = BEToInt(bs, 4);
        us[2] = BEToInt(bs, 8);
        us[3] = BEToInt(bs, 12);
        return us;
    }
    
}
