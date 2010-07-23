package org.bouncycastle.operator.jcajce;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Signature;

class ProviderOperatorHelper
    extends OperatorHelper
{
    private Provider provider;

    ProviderOperatorHelper(Provider provider)
    {
        this.provider = provider;
    }

    protected Signature createSignature(
        String algorithm)
        throws NoSuchAlgorithmException
    {
        return Signature.getInstance(algorithm, provider);
    }

    protected MessageDigest createDigest(
        String algorithm)
        throws NoSuchAlgorithmException
    {
        return MessageDigest.getInstance(algorithm, provider);
    }
}