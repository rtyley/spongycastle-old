package org.bouncycastle.operator.jcajce;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Signature;

class ProviderContentSignerHelper
    extends ContentSignerHelper
{
    private Provider provider;

    ProviderContentSignerHelper(Provider provider)
    {
        this.provider = provider;
    }

    protected Signature createSignature(
        String algorithm)
        throws NoSuchAlgorithmException
    {
        return Signature.getInstance(algorithm, provider);
    }
}