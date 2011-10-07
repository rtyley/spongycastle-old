package org.bouncycastle.eac.jcajce;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

class NamedEACHelper
    extends EACHelper
{
    private final String providerName;

    NamedEACHelper(String providerName)
    {
        this.providerName = providerName;
    }

    protected KeyFactory createKeyFactory(String type)
        throws NoSuchProviderException, NoSuchAlgorithmException
    {
        return KeyFactory.getInstance(type, providerName);
    }
}