package org.bouncycastle.eac.jcajce;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
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
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        return KeyFactory.getInstance(type, provider.getName());
    }
}
