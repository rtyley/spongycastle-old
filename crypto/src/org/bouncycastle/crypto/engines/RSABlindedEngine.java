package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * this does your basic RSA algorithm with blinding
 */
public class RSABlindedEngine
    implements AsymmetricBlockCipher
{
    private static BigInteger ZERO = BigInteger.valueOf(0);

    private RSACoreEngine    core = new RSACoreEngine();
    private RSAKeyParameters key;
    private SecureRandom     random;

    /**
     * initialise the RSA engine.
     *
     * @param forEncryption true if we are encrypting, false otherwise.
     * @param param the necessary RSA key parameters.
     */
    public void init(
        boolean             forEncryption,
        CipherParameters    param)
    {
        core.init(forEncryption, param);

        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom    rParam = (ParametersWithRandom)param;

            key = (RSAKeyParameters)rParam.getParameters();
            random = rParam.getRandom();
        }
        else
        {
            key = (RSAKeyParameters)param;
            random = new SecureRandom();
        }
    }

    /**
     * Return the maximum size for an input block to this engine.
     * For RSA this is always one byte less than the key size on
     * encryption, and the same length as the key size on decryption.
     *
     * @return maximum size for an input block.
     */
    public int getInputBlockSize()
    {
        return core.getInputBlockSize();
    }

    /**
     * Return the maximum size for an output block to this engine.
     * For RSA this is always one byte less than the key size on
     * decryption, and the same length as the key size on encryption.
     *
     * @return maximum size for an output block.
     */
    public int getOutputBlockSize()
    {
        return core.getOutputBlockSize();
    }

    /**
     * Process a single block using the basic RSA algorithm.
     *
     * @param in the input array.
     * @param inOff the offset into the input buffer where the data starts.
     * @param inLen the length of the data to be processed.
     * @return the result of the RSA process.
     * @exception DataLengthException the input block is too large.
     */
    public byte[] processBlock(
        byte[]  in,
        int     inOff,
        int     inLen)
    {
        if (key == null)
        {
            throw new IllegalStateException("RSA engine not initialised");
        }

        if (key instanceof RSAPrivateCrtKeyParameters)
        {
            RSAPrivateCrtKeyParameters k = (RSAPrivateCrtKeyParameters)key;
            BigInteger input = core.convertInput(in, inOff, inLen);
            BigInteger m = k.getModulus();
            BigInteger r = calculateR(m);
            BigInteger result = core.processBlock(r.modPow(k.getPublicExponent(), m).multiply(input).mod(m));

            return core.convertOutput(result.multiply(r.modInverse(m)).mod(m));
        }
        else
        {
            return core.convertOutput(core.processBlock(core.convertInput(in, inOff, inLen)));
        }
    }

    /*
     * calculate a random mess-with-their-heads value.
     */
    private BigInteger calculateR(
        BigInteger m)
    {
        int max = m.bitLength() - 1; // must be less than m.bitLength()
        int min = max / 2;
        int length = ((random.nextInt() & 0xff) * ((max - min) / 0xff)) + min;
        BigInteger factor = new BigInteger(length, random);

        while (factor.equals(ZERO))
        {
            factor = new BigInteger(length, random);
        }

        return factor;
    }
}
