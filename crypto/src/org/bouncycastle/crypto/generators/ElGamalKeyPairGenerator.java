package org.bouncycastle.crypto.generators;

import java.math.BigInteger;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.ElGamalKeyGenerationParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.bouncycastle.crypto.params.ElGamalPublicKeyParameters;

/**
 * a ElGamal key pair generator.
 * <p>
 * This generates keys consistent for use with ElGamal as described in
 * page 164 of "Handbook of Applied Cryptography".
 */
public class ElGamalKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private static BigInteger ZERO = BigInteger.valueOf(0);
    private static BigInteger TWO = BigInteger.valueOf(2);
    
    private ElGamalKeyGenerationParameters param;

    public void init(
        KeyGenerationParameters param)
    {
        this.param = (ElGamalKeyGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        BigInteger           p, g, x, y;
        int                  pLength = param.getStrength();
        ElGamalParameters    elParams = param.getParameters();

        p = elParams.getP();
        g = elParams.getG();
    
        //
        // calculate the private key
        //
        BigInteger pSub2 = p.subtract(TWO);
        
        do
        {
            x = new BigInteger(pLength, param.getRandom());
        }
        while (x.equals(ZERO) || x.compareTo(pSub2) > 0);

        //
        // calculate the public key.
        //
        y = g.modPow(x, p);

        return new AsymmetricCipherKeyPair(
                new ElGamalPublicKeyParameters(y, elParams),
                new ElGamalPrivateKeyParameters(x, elParams));
    }
}
