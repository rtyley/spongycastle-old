package org.bouncycastle.jce.provider;

import java.security.AlgorithmParameterGeneratorSpi;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.IvParameterSpec;

public abstract class JDKAlgorithmParameterGenerator
    extends AlgorithmParameterGeneratorSpi
{
    protected SecureRandom  random;
    protected int           strength = 1024;

    protected void engineInit(
        int             strength,
        SecureRandom    random)
    {
        this.strength = strength;
        this.random = random;
    }

    public static class DES
        extends JDKAlgorithmParameterGenerator
    {
        protected void engineInit(
            AlgorithmParameterSpec  genParamSpec,
            SecureRandom            random)
            throws InvalidAlgorithmParameterException
        {
            throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for DES parameter generation.");
        }

        protected AlgorithmParameters engineGenerateParameters()
        {
            byte[]  iv = new byte[8];

            if (random == null)
            {
                random = new SecureRandom();
            }

            random.nextBytes(iv);

            AlgorithmParameters params;

            try
            {
                params = AlgorithmParameters.getInstance("DES", BouncyCastleProvider.PROVIDER_NAME);
                params.init(new IvParameterSpec(iv));
            }
            catch (Exception e)
            {
                throw new RuntimeException(e.getMessage());
            }

            return params;
        }
    }


}
