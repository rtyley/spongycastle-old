package org.bouncycastle.jce.provider;

import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jce.spec.ECParameterSpec;

class BouncyCastleProviderConfiguration
    implements ProviderConfiguration
{
    private volatile ECParameterSpec ecImplicitCaParams;
    private volatile DHParameterSpec dhDefaultParams;

    void setParameter(String parameterName, Object parameter)
    {
        if (parameterName.equals(ConfigurableProvider.THREAD_LOCAL_EC_IMPLICITLY_CA))
        {
            ECParameterSpec curveSpec;

            if (parameter instanceof ECParameterSpec || parameter == null)
            {
                curveSpec = (ECParameterSpec)parameter;
            }
            else
            {
                throw new IllegalArgumentException("not a valid ECParameterSpec");
            }

            if (curveSpec == null)
            {
                ecImplicitCaParams = null;
            }
            else
            {
                ecImplicitCaParams = (ECParameterSpec)parameter;
            }
        }
        else if (parameterName.equals(ConfigurableProvider.EC_IMPLICITLY_CA))
        {
            if (parameter instanceof ECParameterSpec || parameter == null)
            {
                ecImplicitCaParams = (ECParameterSpec)parameter;
            }
            else
            {
                throw new IllegalArgumentException("not a valid ECParameterSpec");
            }
        }
        else if (parameterName.equals(ConfigurableProvider.THREAD_LOCAL_DH_DEFAULT_PARAMS))
        {
            DHParameterSpec dhSpec;

            if (parameter instanceof DHParameterSpec || parameter == null)
            {
                dhSpec = (DHParameterSpec)parameter;
            }
            else
            {
                throw new IllegalArgumentException("not a valid DHParameterSpec");
            }

            if (dhSpec == null)
            {
                dhDefaultParams = null;
            }
            else
            {
                dhDefaultParams = (DHParameterSpec)parameter;
            }
        }
        else if (parameterName.equals(ConfigurableProvider.DH_DEFAULT_PARAMS))
        {
            if (parameter instanceof DHParameterSpec || parameter == null)
            {
                dhDefaultParams = (DHParameterSpec)parameter;
            }
            else
            {
                throw new IllegalArgumentException("not a valid DHParameterSpec");
            }
        }
    }

    public ECParameterSpec getEcImplicitlyCa()
    {
        return ecImplicitCaParams;
    }

    public DHParameterSpec getDHDefaultParameters()
    {
        return dhDefaultParams;
    }
}
