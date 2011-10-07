package org.bouncycastle.eac.jcajce;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

abstract class EACHelper
{
    public KeyFactory getKeyFactory(String type)
        throws NoSuchProviderException, NoSuchAlgorithmException
    {
        return createKeyFactory(type);
    }

    protected abstract KeyFactory createKeyFactory(String type)
        throws NoSuchProviderException, NoSuchAlgorithmException;
}
