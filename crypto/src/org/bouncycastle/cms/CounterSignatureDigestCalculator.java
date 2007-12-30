package org.bouncycastle.cms;

import java.security.MessageDigest;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;


class CounterSignatureDigestCalculator
    implements DigestCalculator
{
    private final String alg;
    private final String provider;
    private final byte[] data;

    CounterSignatureDigestCalculator(String alg, String provider, byte[] data)
    {
        this.alg = alg;
        this.provider = provider;
        this.data = data;
    }

    public byte[] getDigest()
        throws NoSuchProviderException, NoSuchAlgorithmException
    {
        MessageDigest digest = CMSSignedHelper.INSTANCE.getDigestInstance(alg, provider);

        return digest.digest(data);
    }
}
