package org.bouncycastle.jce.provider;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.interfaces.ConfigurableProvider;

class ProviderUtil
{
    private static volatile ECParameterSpec implicitlyCaCurve;

    static void setParameter(String parameterName, Object parameter)
    {
        if (parameterName.equals(ConfigurableProvider.EC_IMPLICITLY_CA))
        {
            implicitlyCaCurve = (ECParameterSpec)parameter;
        }
    }

    static ECParameterSpec getEcImplicitlyCa()
    {
        return implicitlyCaCurve;
    }
}
