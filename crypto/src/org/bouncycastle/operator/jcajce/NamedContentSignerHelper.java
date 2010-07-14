package org.bouncycastle.operator.jcajce;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;

class NamedContentSignerHelper
    extends ContentSignerHelper
{
    private String providerName;

    NamedContentSignerHelper(String providerName)
    {
        this.providerName = providerName;
    }

    protected Signature createSignature(
        String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        return Signature.getInstance(algorithm, providerName);
    }
}