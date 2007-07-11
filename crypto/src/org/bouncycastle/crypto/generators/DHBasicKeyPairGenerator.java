package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;

import java.math.BigInteger;

/**
 * a basic Diffie-Helman key pair generator.
 *
 * This generates keys consistent for use with the basic algorithm for
 * Diffie-Helman.
 */
public class DHBasicKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private DHKeyGeneratorHelper helper = DHKeyGeneratorHelper.INSTANCE;
    private DHKeyGenerationParameters param;

    public void init(
        KeyGenerationParameters param)
    {
        this.param = (DHKeyGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        BigInteger      p, x, y;
        DHParameters    dhParams = param.getParameters();

        p = dhParams.getP();
        x = helper.calculatePrivate(p, param.getRandom(), dhParams.getL()); 
        y = helper.calculatePublic(p, dhParams.getG(), x);

        return new AsymmetricCipherKeyPair(
                new DHPublicKeyParameters(y, dhParams),
                new DHPrivateKeyParameters(x, dhParams));
    }
}
