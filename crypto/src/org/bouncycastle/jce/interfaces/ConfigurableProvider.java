package org.bouncycastle.jce.interfaces;

/**
 * Implemented by the BC provider. This allows setting of hidden parameters,
 * such as the ImplicitCA parameters from X.962if used.
 */
public interface ConfigurableProvider
{
    static final String      EC_IMPLICITLY_CA = "ecImplicitlyCa";

    void setParameter(String parameterName, Object parameter);
}
