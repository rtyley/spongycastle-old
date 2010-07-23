package org.bouncycastle.operator.jcajce;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;

class NamedOperatorHelper
    extends OperatorHelper
{
    private String providerName;

    NamedOperatorHelper(String providerName)
    {
        this.providerName = providerName;
    }

    protected Signature createSignature(
        String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        return Signature.getInstance(algorithm, providerName);
    }

    protected MessageDigest createDigest(
        String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        return MessageDigest.getInstance(algorithm, providerName);
    }

}