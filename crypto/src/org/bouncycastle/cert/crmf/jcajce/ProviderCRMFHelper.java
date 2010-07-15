package org.bouncycastle.cert.crmf.jcajce;

import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;

import javax.crypto.Mac;


class ProviderCRMFHelper
    extends CRMFHelper
{
    private Provider provider;

    ProviderCRMFHelper(Provider provider)
    {
        this.provider = provider;
    }

    protected KeyFactory createKeyFactory(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        return KeyFactory.getInstance(algorithm, provider);
    }

    protected MessageDigest createDigest(String algorithm)
        throws NoSuchAlgorithmException
    {
        return MessageDigest.getInstance(algorithm, provider);
    }

    protected Mac createMac(String algorithm)
        throws NoSuchAlgorithmException
    {
        return Mac.getInstance(algorithm, provider);
    }
}