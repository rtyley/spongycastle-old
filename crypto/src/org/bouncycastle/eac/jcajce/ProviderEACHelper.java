package org.bouncycastle.eac.jcajce;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

class ProviderEACHelper
    extends EACHelper
{
    private final Provider provider;

    ProviderEACHelper(Provider provider)
    {
        this.provider = provider;
    }

    protected KeyFactory createKeyFactory(String type)
        throws NoSuchAlgorithmException
    {
        return KeyFactory.getInstance(type, provider);
    }
}