package org.bouncycastle.jce.provider;

import org.bouncycastle.jce.interfaces.ConfigurableProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

class ProviderUtil
{
    private static volatile ECParameterSpec implicitlyCaCurve;

    static void setParameter(String parameterName, Object parameter)
    {
        if (parameterName.equals(ConfigurableProvider.EC_IMPLICITLY_CA))
        {
            if (parameter instanceof ECParameterSpec)
            {
                implicitlyCaCurve = (ECParameterSpec)parameter;
            }
            else  // assume java.security.spec
            {
                implicitlyCaCurve = EC5Util.convertSpec((java.security.spec.ECParameterSpec)parameter, false);
            }
        }
    }

    static ECParameterSpec getEcImplicitlyCa()
    {
        return implicitlyCaCurve;
    }
}
