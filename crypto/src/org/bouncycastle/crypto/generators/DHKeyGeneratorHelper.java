package org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

class DHKeyGeneratorHelper
{
    static final DHKeyGeneratorHelper INSTANCE = new DHKeyGeneratorHelper();
    
    private static BigInteger ZERO = BigInteger.valueOf(0);
    private static BigInteger TWO = BigInteger.valueOf(2);
    
    private DHKeyGeneratorHelper()
    {
    }
    
    BigInteger calculatePrivate(BigInteger p, SecureRandom random, int limit)
    {
        //
        // calculate the private key
        //
        BigInteger pSub2 = p.subtract(TWO);
        BigInteger x;
        
        if (limit == 0)
        {
            int pLength = p.bitLength();
            
            do
            {
                x = new BigInteger(pLength, random);
            }
            while (x.equals(ZERO) || x.compareTo(pSub2) > 0);
        }
        else
        {
            x = new BigInteger(limit, random);
        }
        
        return x;
    }
    
    BigInteger calculatePublic(BigInteger p, BigInteger g, BigInteger x)
    {
        return g.modPow(x, p);
    }
}
