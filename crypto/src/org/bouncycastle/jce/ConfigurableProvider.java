package org.bouncycastle.jce;

import org.bouncycastle.jce.spec.ECParameterSpec;

/**
 * Implemented by the BC provider. This allows setting of hidden parameters,
 * such as the ImplicitCA parameters from X.962if used.
 */
public interface ConfigurableProvider
{
    void setImplicitCaEC(ECParameterSpec curve);
}
