package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.ExtendedDigest;

/**
 * implementation of SHA-3 based on Keccak-simple.c from http://keccak.noekeon.org/
 * 
 * Following the naming conventions used in the C source code to enable easy review of the implementation.
 */
public class SHA3Digest implements ExtendedDigest {

    private static final int    cKeccakB               = 1600;
    private static final int    cKeccakR               = 1024;
    private static final int    cKeccakR_SizeInBytes   = (cKeccakR / 8);
    private static final int    crypto_hash_BYTES      = cKeccakR_SizeInBytes;
    private static final int    cKeccakNumberOfRounds  = 24;

    private static final int    cKeccakLaneSizeInBits  = 64;                                 // size of a long

    private static final long[] KeccakF_RoundConstants = {
                    0x0000000000000001L,
                    0x0000000000008082L,
                    0x800000000000808aL,
                    0x8000000080008000L,
                    0x000000000000808bL,
                    0x0000000080000001L,
                    0x8000000080008081L,
                    0x8000000000008009L,
                    0x000000000000008aL,
                    0x0000000000000088L,
                    0x0000000080008009L,
                    0x000000008000000aL,
                    0x000000008000808bL,
                    0x800000000000008bL,
                    0x8000000000008089L,
                    0x8000000000008003L,
                    0x8000000000008002L,
                    0x8000000000000080L,
                    0x000000000000800aL,
                    0x800000008000000aL,
                    0x8000000080008081L,
                    0x8000000000008080L,
                    0x0000000080000001L,
                    0x8000000080008008L               };

    private static final int    DIGEST_LENGTH          = 1600 / 8;

    // registers
    //
    private long[]              _state                 = new long[5 * 5];
    private byte[]              _temp                  = new byte[DIGEST_LENGTH];

    //
    // buffers
    //
    private byte[]              _in                    = new byte[cKeccakLaneSizeInBits / 8];
    private int                 _inOff                 = 0;

    private long[]              _out                   = new long[cKeccakLaneSizeInBits / 8];
    private int                 _outOff                = 0;

    /**
     * Standard constructor
     */
    public SHA3Digest() {
        reset();
    }

    /**
     * Copy constructor. This will copy the state of the provided message digest.
     */
    public SHA3Digest(SHA3Digest t) {
        throw new IllegalStateException("Not yet implemented");
    }

    public String getAlgorithmName() {
        return "SHA3";
    }

    public int getDigestSize() {
        return DIGEST_LENGTH;
    }

    private void processWord(byte[] b, int off) {
        x[xOff++] = ((long) (b[off + 7] & 0xff) << 56) | ((long) (b[off + 6] & 0xff) << 48)
                        | ((long) (b[off + 5] & 0xff) << 40) | ((long) (b[off + 4] & 0xff) << 32)
                        | ((long) (b[off + 3] & 0xff) << 24) | ((long) (b[off + 2] & 0xff) << 16)
                        | ((long) (b[off + 1] & 0xff) << 8) | ((b[off + 0] & 0xff));

        if (xOff == x.length) {
            processBlock();
        }

        bOff = 0;
    }

    public void update(byte in) {
        buf[bOff++] = in;

        if (bOff == buf.length) {
            processWord(buf, 0);
        }

        byteCount++;
    }

    public void update(byte[] in, int inOff, int len) {
        //
        // fill the current word
        //
        while ((bOff != 0) && (len > 0)) {
            update(in[inOff]);

            inOff++;
            len--;
        }

        //
        // process whole words.
        //
        while (len > 8) {
            processWord(in, inOff);

            inOff += 8;
            len -= 8;
            byteCount += 8;
        }

        //
        // load in the remainder.
        //
        while (len > 0) {
            update(in[inOff]);

            inOff++;
            len--;
        }
    }

    private void processBlock() {
        //
        // save abc
        //
        long aa = a;
        long bb = b;
        long cc = c;

        //
        // rounds and schedule
        //
        roundABC(x[0], 5);
        roundBCA(x[1], 5);
        roundCAB(x[2], 5);
        roundABC(x[3], 5);
        roundBCA(x[4], 5);
        roundCAB(x[5], 5);
        roundABC(x[6], 5);
        roundBCA(x[7], 5);

        keySchedule();

        roundCAB(x[0], 7);
        roundABC(x[1], 7);
        roundBCA(x[2], 7);
        roundCAB(x[3], 7);
        roundABC(x[4], 7);
        roundBCA(x[5], 7);
        roundCAB(x[6], 7);
        roundABC(x[7], 7);

        keySchedule();

        roundBCA(x[0], 9);
        roundCAB(x[1], 9);
        roundABC(x[2], 9);
        roundBCA(x[3], 9);
        roundCAB(x[4], 9);
        roundABC(x[5], 9);
        roundBCA(x[6], 9);
        roundCAB(x[7], 9);

        //
        // feed forward
        //
        a ^= aa;
        b -= bb;
        c += cc;

        //
        // clear the x buffer
        //
        xOff = 0;
        for (int i = 0; i != x.length; i++) {
            x[i] = 0;
        }
    }

    public void unpackWord(long r, byte[] out, int outOff) {
        out[outOff + 7] = (byte) (r >> 56);
        out[outOff + 6] = (byte) (r >> 48);
        out[outOff + 5] = (byte) (r >> 40);
        out[outOff + 4] = (byte) (r >> 32);
        out[outOff + 3] = (byte) (r >> 24);
        out[outOff + 2] = (byte) (r >> 16);
        out[outOff + 1] = (byte) (r >> 8);
        out[outOff] = (byte) r;
    }

    private void processLength(long bitLength) {
        x[7] = bitLength;
    }

    private void finish() {
        long bitLength = (byteCount << 3);

        update((byte) 0x01);

        while (bOff != 0) {
            update((byte) 0);
        }

        processLength(bitLength);

        processBlock();
    }

    public int doFinal(byte[] out, int outOff) {
        finish();

        unpackWord(a, out, outOff);
        unpackWord(b, out, outOff + 8);
        unpackWord(c, out, outOff + 16);

        reset();

        return DIGEST_LENGTH;
    }

    /**
     * reset the chaining variables
     */
    public void reset() {
        xOff = 0;
        for (int i = 0; i != x.length; i++) {
            x[i] = 0;
        }

        bOff = 0;
        for (int i = 0; i != buf.length; i++) {
            buf[i] = 0;
        }

        byteCount = 0;

    }

    public int getByteLength() {
        return BYTE_LENGTH;
    }
}
