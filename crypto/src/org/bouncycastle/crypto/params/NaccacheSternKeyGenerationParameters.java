package org.bouncycastle.crypto.params;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Parameters for NaccacheStern public private key generation. For details on
 * this cipher, please see
 * 
 * http://www.gemplus.com/smart/rd/publications/pdf/NS98pkcs.pdf
 */
public class NaccacheSternKeyGenerationParameters extends KeyGenerationParameters
{

    // private BigInteger publicExponent;
    private int certainty;

    private int cntSmallPrimes;

    /**
     * Parameters for generating a NaccacheStern KeyPair.
     * 
     * @param random
     *            The source of randomness
     * @param strength
     *            The desired strength of the Key in Bits
     * @param certainty
     *            the probability that the generated primes are not really prime
     *            as integer: 2^(-certainty) is then the probability
     * @param cntSmallPrimes
     *            How many small key factors are desired
     */
    public NaccacheSternKeyGenerationParameters(SecureRandom random, int strength, int certainty, int cntSmallPrimes)
    {
        super(random, strength);

        this.certainty = certainty;
        if (cntSmallPrimes % 2 == 1)
        {
            throw new IllegalArgumentException("cntSmallPrimes must be a multiple of 2");
        }
        if (cntSmallPrimes < 30)
        {
            throw new IllegalArgumentException("cntSmallPrimes must be >= 30 for security reasons");
        }
        this.cntSmallPrimes = cntSmallPrimes;
    }

    /**
     * @return Returns the certainty.
     */
    public int getCertainty()
    {
        return certainty;
    }

    /**
     * @return Returns the cntSmallPrimes.
     */
    public int getCntSmallPrimes()
    {
        return cntSmallPrimes;
    }
}
