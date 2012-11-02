package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.gcm.GCMMultiplier;
import org.bouncycastle.crypto.modes.gcm.Tables8kGCMMultiplier;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.util.Pack;
import org.bouncycastle.util.Arrays;

/**
 * Implements the Galois/Counter mode (GCM) detailed in
 * NIST Special Publication 800-38D.
 */
public class GCMBlockCipher
    implements AEADBlockCipher
{
    private static final int BLOCK_SIZE = 16;

    // not final due to a compiler bug 
    private BlockCipher   cipher;
    private GCMMultiplier multiplier;

    // These fields are set by init and not modified by processing
    private boolean             forEncryption;
    private int                 macSize;
    private byte[]              nonce;
    private byte[]              initialAssociatedText;
    private byte[]              H;
    private byte[]              J0;

    // These fields are modified during processing
    private byte[]      bufBlock;
    private byte[]      macBlock;
    private byte[]      S;
    private byte[]      counter;
    private int         bufOff;
    private long        totalLength;
    private boolean     cipherInitialized;
    private byte[]      atBlock;
    private int         atBlockPos;
    private long        atLength;

    public GCMBlockCipher(BlockCipher c)
    {
        this(c, null);
    }

    public GCMBlockCipher(BlockCipher c, GCMMultiplier m)
    {
        if (c.getBlockSize() != BLOCK_SIZE)
        {
            throw new IllegalArgumentException(
                "cipher required with a block size of " + BLOCK_SIZE + ".");
        }

        if (m == null)
        {
            // TODO Consider a static property specifying default multiplier
            m = new Tables8kGCMMultiplier();
        }

        this.cipher = c;
        this.multiplier = m;
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
        this.macBlock = null;

        KeyParameter keyParam;

        if (params instanceof AEADParameters)
        {
            AEADParameters param = (AEADParameters)params;

            nonce = param.getNonce();
            initialAssociatedText = param.getAssociatedText();

            int macSizeBits = param.getMacSize();
            if (macSizeBits < 96 || macSizeBits > 128 || macSizeBits % 8 != 0)
            {
                throw new IllegalArgumentException("Invalid value for MAC size: " + macSizeBits);
            }

            macSize = macSizeBits / 8; 
            keyParam = param.getKey();
        }
        else if (params instanceof ParametersWithIV)
        {
            ParametersWithIV param = (ParametersWithIV)params;

            nonce = param.getIV();
            initialAssociatedText  = null;
            macSize = 16;
            keyParam = (KeyParameter)param.getParameters();
        }
        else
        {
            throw new IllegalArgumentException("invalid parameters passed to GCM");
        }

        int bufLength = forEncryption ? BLOCK_SIZE : (BLOCK_SIZE + macSize); 
        this.bufBlock = new byte[bufLength];

        if (nonce == null || nonce.length < 1)
        {
            throw new IllegalArgumentException("IV must be at least 1 byte");
        }

        // TODO This should be configurable by init parameters
        // (but must be 16 if nonce length not 12) (BLOCK_SIZE?)
//        this.tagLength = 16;

        // Cipher always used in forward mode
        // if keyParam is null we're reusing the last key.
        if (keyParam != null)
        {
            cipher.init(true, keyParam);

            this.H = new byte[BLOCK_SIZE];
            cipher.processBlock(H, 0, H, 0);

            // GCMMultiplier tables don't change unless the key changes (and are expensive to init)
            multiplier.init(H);
        }

        this.J0 = new byte[BLOCK_SIZE];

        if (nonce.length == 12)
        {
            System.arraycopy(nonce, 0, J0, 0, nonce.length);
            this.J0[BLOCK_SIZE - 1] = 0x01;
        }
        else
        {
            gHASH(J0, nonce, nonce.length);
            byte[] X = new byte[BLOCK_SIZE];
            packLength((long)nonce.length * 8, X, 8);
            gHASHBlock(J0, X);
        }

        this.S = new byte[BLOCK_SIZE];
        this.atBlock = new byte[BLOCK_SIZE];
        this.atBlockPos = 0;
        this.atLength = 0;
        this.counter = Arrays.clone(J0);
        this.bufOff = 0;
        this.totalLength = 0;

        if (initialAssociatedText != null)
        {
            processAADBytes(initialAssociatedText, 0, initialAssociatedText.length);
        }
    }

    public byte[] getMac()
    {
        return Arrays.clone(macBlock);
    }

    public int getOutputSize(int len)
    {
        int totalData = len + bufOff;

        if (forEncryption)
        {
             return totalData + macSize;
        }

        return totalData < macSize ? 0 : totalData - macSize;
    }

    public int getUpdateOutputSize(int len)
    {
        int totalData = len + bufOff;
        if (!forEncryption)
        {
            if (totalData < macSize)
            {
                return 0;
            }
            totalData -= macSize;
        }
        return totalData - totalData % BLOCK_SIZE;
    }

    public void processAADByte(byte in)
    {
        /*
         *  TODO Lift this restriction by tracking separate hashes for the associated data and encrypted data
         *  (see GCMReorderTest for example code on how to calculate the final hash from the separate ones). 
         */
        if (cipherInitialized)
        {
            throw new IllegalStateException("AAD data cannot be added after encryption/decription processing has begun.");
        }

        atBlock[atBlockPos] = in;
        if (++atBlockPos == BLOCK_SIZE)
        {
            // Hash each block as it fills
            gHASHBlock(S, atBlock);
            atBlockPos = 0;
            atLength += BLOCK_SIZE;
        }
    }

    public void processAADBytes(byte[] in, int inOff, int len)
    {
        /*
         *  TODO Lift this restriction by tracking separate hashes for the associated data and encrypted data
         *  (see GCMReorderTest for example code on how to calculate the final hash from the separate ones). 
         */
        if (cipherInitialized)
        {
            throw new IllegalStateException("AAD data cannot be added after encryption/decription processing has begun.");
        }

        for (int i = 0; i < len; ++i)
        {
            atBlock[atBlockPos] = in[inOff + i];
            if (++atBlockPos == BLOCK_SIZE)
            {
                // Hash each block as it fills
                gHASHBlock(S, atBlock);
                atBlockPos = 0;
                atLength += BLOCK_SIZE;
            }
        }
    }

    private void initCipher()
    {
        if (cipherInitialized)
        {
            return;
        }

        cipherInitialized = true;

        // Finish hash for partial AD block
        if (atBlockPos > 0)
        {
            gHASHPartial(S, atBlock, 0, atBlockPos);
            atLength += atBlockPos;
        }
    }

    public int processByte(byte in, byte[] out, int outOff)
        throws DataLengthException
    {
        initCipher();

        bufBlock[bufOff] = in;
        if (++bufOff == bufBlock.length)
        {
            gCTRBlock(bufBlock, out, outOff);
            if (forEncryption)
            {
                bufOff = 0;
            }
            else
            {
                System.arraycopy(bufBlock, BLOCK_SIZE, bufBlock, 0, macSize);
                bufOff = macSize;
            }
            return BLOCK_SIZE;
        }

        return 0;
    }

    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
        throws DataLengthException
    {
        initCipher();

        int resultLen = 0;

        for (int i = 0; i < len; ++i)
        {
            bufBlock[bufOff] = in[inOff + i];
            if (++bufOff == bufBlock.length)
            {
                gCTRBlock(bufBlock, out, outOff + resultLen);
                if (forEncryption)
                {
                    bufOff = 0;
                }
                else
                {
                    System.arraycopy(bufBlock, BLOCK_SIZE, bufBlock, 0, macSize);
                    bufOff = macSize;
                }
                resultLen += BLOCK_SIZE;
            }
        }

        return resultLen;
    }

    public int doFinal(byte[] out, int outOff)
        throws IllegalStateException, InvalidCipherTextException
    {
        initCipher();

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
            gCTRPartial(bufBlock, 0, extra, out, outOff);
        }

        // Final gHASH
        byte[] X = new byte[BLOCK_SIZE];
        packLength(atLength * 8, X, 0);
        packLength(totalLength * 8, X, 8);

        gHASHBlock(S, X);

        // TODO Fix this if tagLength becomes configurable
        // T = MSBt(GCTRk(J0,S))
        byte[] tag = new byte[BLOCK_SIZE];
        cipher.processBlock(J0, 0, tag, 0);
        xor(tag, S);

        int resultLen = extra;

        // We place into macBlock our calculated value for T
        this.macBlock = new byte[macSize];
        System.arraycopy(tag, 0, macBlock, 0, macSize);

        if (forEncryption)
        {
            // Append T to the message
            System.arraycopy(macBlock, 0, out, outOff + bufOff, macSize);
            resultLen += macSize;
        }
        else
        {
            // Retrieve the T value from the message and compare to calculated one
            byte[] msgMac = new byte[macSize];
            System.arraycopy(bufBlock, extra, msgMac, 0, macSize);
            if (!Arrays.constantTimeAreEqual(this.macBlock, msgMac))
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
        cipher.reset();

        S = new byte[BLOCK_SIZE];
        atBlock = new byte[BLOCK_SIZE];
        atBlockPos = 0;
        atLength = 0;
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

        cipherInitialized = false;

        if (initialAssociatedText != null)
        {
            processAADBytes(initialAssociatedText, 0, initialAssociatedText.length);
        }
    }

    private void gCTRBlock(byte[] block, byte[] out, int outOff)
    {
        byte[] tmp = getNextCounterBlock();

        xor(tmp, block);
        System.arraycopy(tmp, 0, out, outOff, BLOCK_SIZE);

        gHASHBlock(S, forEncryption ? tmp : block);

        totalLength += BLOCK_SIZE;
    }

    private void gCTRPartial(byte[] buf, int off, int len, byte[] out, int outOff)
    {
        byte[] tmp = getNextCounterBlock();

        xor(tmp, buf, off, len);
        System.arraycopy(tmp, 0, out, outOff, len);

        gHASHPartial(S, forEncryption ? tmp : buf, 0, len);

        totalLength += len;
    }

    private void gHASH(byte[] Y, byte[] b, int len)
    {
        for (int pos = 0; pos < len; pos += BLOCK_SIZE)
        {
            int num = Math.min(len - pos, BLOCK_SIZE);
            gHASHPartial(Y, b, pos, num);
        }
    }

    private void gHASHBlock(byte[] Y, byte[] b)
    {
        xor(Y, b);
        multiplier.multiplyH(Y);
    }

    private void gHASHPartial(byte[] Y, byte[] b, int off, int len)
    {
        xor(Y, b, off, len);
        multiplier.multiplyH(Y);
    }

    private byte[] getNextCounterBlock()
    {
        for (int i = 15; i >= 12; --i)
        {
            byte b = (byte)((counter[i] + 1) & 0xff);
            counter[i] = b;

            if (b != 0)
            {
                break;
            }
        }

        byte[] tmp = new byte[BLOCK_SIZE];
        cipher.processBlock(counter, 0, tmp, 0);
        return tmp;
    }

    private static void xor(byte[] block, byte[] val)
    {
        for (int i = 15; i >= 0; --i)
        {
            block[i] ^= val[i];
        }
    }

    private static void xor(byte[] block, byte[] val, int off, int len)
    {
        while (--len >= 0)
        {
            block[len] ^= val[off + len];
        }
    }

    private static void packLength(long count, byte[] bs, int off)
    {
        Pack.intToBigEndian((int)(count >>> 32), bs, off); 
        Pack.intToBigEndian((int)count, bs, off + 4);
    }
}
