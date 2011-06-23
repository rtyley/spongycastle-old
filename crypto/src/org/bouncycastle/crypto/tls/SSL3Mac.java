package org.bouncycastle.crypto.tls;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

/**
 * HMAC implementation based on original internet draft for HMAC (RFC 2104)
 * 
 * The difference is that padding is concatentated versus XORed with the key
 * 
 * H(K + opad, H(K + ipad, text))
 */
public class SSL3Mac implements Mac
{
    private final static byte IPAD = (byte)0x36;
    private final static byte OPAD = (byte)0x5C;

    private Digest digest;

    private byte[] secret;
    private byte[] ipad, opad;

    /**
     * Base constructor for one of the standard digest algorithms that the byteLength of
     * the algorithm is know for. Behaviour is undefined for digests other than MD5 or SHA1.
     * 
     * @param digest the digest.
     */
    public SSL3Mac(Digest digest)
    {
        this.digest = digest;

        int padLength = digest.getDigestSize() == 20 ? 40 : 64 - digest.getDigestSize();

        this.ipad = genPad(IPAD, padLength);
        this.opad = genPad(OPAD, padLength);
    }

    public String getAlgorithmName()
    {
        return digest.getAlgorithmName() + "/SSL3MAC";
    }

    public Digest getUnderlyingDigest()
    {
        return digest;
    }

    public void init(CipherParameters params)
    {
        secret = Arrays.clone(((KeyParameter)params).getKey());

        reset();
    }

    public int getMacSize()
    {
        return digest.getDigestSize();
    }

    public void update(byte in)
    {
        digest.update(in);
    }

    public void update(byte[] in, int inOff, int len)
    {
        digest.update(in, inOff, len);
    }

    public int doFinal(byte[] out, int outOff)
    {
        byte[] tmp = new byte[digest.getDigestSize()];
        digest.doFinal(tmp, 0);

        digest.update(secret, 0, secret.length);
        digest.update(opad, 0, opad.length);
        digest.update(tmp, 0, tmp.length);

        int len = digest.doFinal(out, outOff);

        reset();

        return len;
    }

    /**
     * Reset the mac generator.
     */
    public void reset()
    {
        digest.reset();
        digest.update(secret, 0, secret.length);
        digest.update(ipad, 0, ipad.length);
    }

    private static byte[] genPad(byte b, int count)
    {
        byte[] padding = new byte[count];
        Arrays.fill(padding, b);
        return padding;
    }
}
