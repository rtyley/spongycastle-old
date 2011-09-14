package org.bouncycastle.jcajce.provider.util;

import org.bouncycastle.jce.interfaces.ConfigurableProvider;

public abstract class AlgorithmProvider
{
    public abstract void configure(ConfigurableProvider provider);
}
