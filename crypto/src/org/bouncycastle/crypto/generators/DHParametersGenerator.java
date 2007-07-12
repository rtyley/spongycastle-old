package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.params.DHParameters;

import java.math.BigInteger;
import java.security.SecureRandom;

public class DHParametersGenerator
{
    private int             size;
    private int             certainty;
    private SecureRandom    random;

    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    /**
     * Initialise the parameters generator.
     * 
     * @param size bit length for the prime p
     * @param certainty level of certainty for the prime number tests
     * @param random  a source of randomness
     */
    public void init(
        int             size,
        int             certainty,
        SecureRandom    random)
    {
        this.size = size;
        this.certainty = certainty;
        this.random = random;
    }

    /**
     * which generates the p and g values from the given parameters,
     * returning the DHParameters object.
     * <p>
     * Note: can take a while...
     */
    public DHParameters generateParameters()
    {
        //
        // find a safe prime p where p = 2*q + 1, where p and q are prime.
        //
        BigInteger[] safePrimes = DHParametersHelper.generateSafePrimes(size, certainty, random);

        BigInteger p = safePrimes[0];
        BigInteger q = safePrimes[1];

        BigInteger pMinusTwo = p.subtract(TWO);
        BigInteger g;

        //
        // calculate the generator g - the advantage of using the 2q+1 
        // approach is that we know the prime factorisation of (p - 1)...
        //

        // Handbook of Applied Cryptography 4.86
        do
        {
            g = createInRange(TWO, pMinusTwo, random);
        }
        while (g.modPow(TWO, p).equals(ONE)
            || g.modPow(q, p).equals(ONE));

/*
        // RFC 2631 2.1.1 (and see Handbook of Applied Cryptography 4.81)
        do
        {
            BigInteger h = createInRange(TWO, pMinusTwo, random);

            g = h.modPow(TWO, p);
        }
        while (g.equals(ONE));
*/

        return new DHParameters(p, g, q, TWO, null);
    }

    private static BigInteger createInRange(
        BigInteger      min,
        BigInteger      max,
        SecureRandom    random)
    {
        BigInteger x;
        do
        {
            x = new BigInteger(max.bitLength(), random);
        }
        while (x.compareTo(min) < 0 || x.compareTo(max) > 0);
        return x;
    }
}
