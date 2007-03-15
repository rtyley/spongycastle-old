package org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

class DHParametersHelper
{
    private static BigInteger ONE = BigInteger.valueOf(1);

    // Finds a pair of prime BigInteger's {p, q: p = 2q + 1}
    static BigInteger[] generateSafePrimes(
        int             size,
        int             certainty,
        SecureRandom    random)
    {
        BigInteger p, q;
        int qLength = size - 1;

        for (;;)
        {
            q = new BigInteger(qLength, 2, random);

            // p <- 2q + 1
            p = q.shiftLeft(1).add(ONE);

            if (p.isProbablePrime(certainty)
                && (certainty <= 2 || q.isProbablePrime(certainty)))
            {
                    break;
            }
        }

        return new BigInteger[] { p, q };
    }
}
