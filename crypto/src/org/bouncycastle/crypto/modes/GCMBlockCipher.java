package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;

/**
 * Implements the Galois/Counter mode (GCM) detailed in
 * NIST Special Publication 800-38D.
 */
public class GCMBlockCipher
    implements AEADBlockCipher
{
    private static final int    BLOCK_SIZE = 16;
    private static final byte[] ZEROES = new byte[BLOCK_SIZE];
    private static final BigInteger R = new BigInteger("11100001", 2).shiftLeft(120);
    private static final BigInteger ZERO = BigInteger.valueOf(0);

    private final BlockCipher   cipher;

    // These fields are set by init and not modified by processing
    private boolean             forEncryption;
    private int                 macSize;
    private byte[]              nonce;
    private byte[]              A;
    private KeyParameter        keyParam;
//    private int                 tagLength;
    private BigInteger          H;
    private BigInteger          initS;
    private byte[]              J0;

    // These fields are modified during processing
    private byte[]      bufBlock;
    private byte[]      macBlock;
    private BigInteger  S;
    private byte[]      counter;
    private int         bufOff;
    private long        totalLength;

    // Debug variables
//    private int nCount, xCount, yCount;

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

        byte[] h = new byte[BLOCK_SIZE];
        cipher.processBlock(ZEROES, 0, h, 0);
        //trace("H: " + new String(Hex.encode(h)));
        this.H = new BigInteger(1, h);
        this.initS = gHASH(A, false);

        if (nonce.length == 12)
        {
            this.J0 = new byte[16];
            System.arraycopy(nonce, 0, J0, 0, nonce.length);
            this.J0[15] = 0x01;
        }
        else
        {
            BigInteger N = gHASH(nonce, true);
            BigInteger X = BigInteger.valueOf(nonce.length * 8);
            //trace("len({})||len(IV): " + dumpBigInt(X));

            N = multiply(N.xor(X), H);
            //trace("GHASH(H,{},IV): " + dumpBigInt(N));
            this.J0 = asBlock(N);
        }

        this.S = initS;
        this.counter = Arrays.clone(J0);
        //trace("Y" + yCount + ": " + new String(Hex.encode(counter)));
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
        else
        {
             return len + bufOff - macSize;
        }
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
            resultLen += process(in[inOff + i], out, outOff + resultLen);
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
        BigInteger X = BigInteger.valueOf(A.length * 8).shiftLeft(64).add(
            BigInteger.valueOf(totalLength * 8));
        //trace("len(A)||len(C): " + dumpBigInt(X));

        S = multiply(S.xor(X), H);
        //trace("GHASH(H,A,C): " + dumpBigInt(S));

        // T = MSBt(GCTRk(J0,S))
        byte[] tBytes = new byte[BLOCK_SIZE];
        cipher.processBlock(J0, 0, tBytes, 0);
        //trace("E(K,Y0): " + new String(Hex.encode(tmp)));
        BigInteger T = S.xor(new BigInteger(1, tBytes));

        // TODO Fix this if tagLength becomes configurable
        byte[] tag = asBlock(T);
        //trace("T: " + new String(Hex.encode(tag)));

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
        // Debug
//        nCount = xCount = yCount = 0;

        S = initS;
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
        //trace("Y" + ++yCount + ": " + new String(Hex.encode(counter)));

        byte[] tmp = new byte[BLOCK_SIZE];
        cipher.processBlock(counter, 0, tmp, 0);
        //trace("E(K,Y" + yCount + "): " + new String(Hex.encode(tmp)));

        if (forEncryption)
        {
            System.arraycopy(ZEROES, bufCount, tmp, bufCount, BLOCK_SIZE - bufCount);

            for (int i = bufCount - 1; i >= 0; --i)
            {
                tmp[i] ^= buf[i];
                out[outOff + i] = tmp[i];
            }

            gHASHBlock(tmp);
        }
        else
        {
            for (int i = bufCount - 1; i >= 0; --i)
            {
                tmp[i] ^= buf[i];
                out[outOff + i] = tmp[i];
            }

            gHASHBlock(buf);
        }

        totalLength += bufCount;
    }

    private BigInteger gHASH(byte[] b, boolean nonce)
    {
        //trace("" + b.length);
        BigInteger Y = ZERO;

        for (int pos = 0; pos < b.length; pos += 16)
        {
            byte[] x = new byte[16];
            int num = Math.min(b.length - pos, 16);
            System.arraycopy(b, pos, x, 0, num);
            BigInteger X = new BigInteger(1, x);
            Y = multiply(Y.xor(X), H);
//            if (nonce)
//            {
//                trace("N" + ++nCount + ": " + dumpBigInt(Y));
//            }
//            else
//            {
//                trace("X" + ++xCount + ": " + dumpBigInt(Y) + " (gHASH)");
//            }
        }

        return Y;
    }

    private void gHASHBlock(byte[] block)
    {
        if (block.length > BLOCK_SIZE)
        {
            byte[] tmp = new byte[BLOCK_SIZE];
            System.arraycopy(block, 0, tmp, 0, BLOCK_SIZE);
            block = tmp;
        }

        BigInteger X = new BigInteger(1, block);
        S = multiply(S.xor(X), H);
        //trace("X" + ++xCount + ": " + dumpBigInt(S) + " (gHASHBlock)");
    }

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

    private BigInteger multiply(BigInteger X, BigInteger Y)
    {
        BigInteger Z = ZERO;
        BigInteger V = X;

        for (int i = 0; i < 128; ++i)
        {
            if (Y.testBit(127 - i))
            {
                Z = Z.xor(V);
            }

            boolean lsb = V.testBit(0);
            V = V.shiftRight(1);
            if (lsb)
            {
                V = V.xor(R);
            }
        }

        return Z;
    }

    private byte[] asBlock(BigInteger bi)
    {
        byte[] b = BigIntegers.asUnsignedByteArray(bi);
        if (b.length < 16)
        {
            byte[] tmp = new byte[16];
            System.arraycopy(b, 0, tmp, tmp.length - b.length, b.length);
            b = tmp;
        }
        return b;
    }

//    private String dumpBigInt(BigInteger bi)
//    {
//        byte[] b = asBlock(bi);
//
//        return new String(Hex.encode(b));         
//    }
//
//    private void trace(String msg)
//    {
//        System.err.println(msg);
//    }
}
