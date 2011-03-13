package org.spongycastle.cms;

import org.spongycastle.util.Arrays;

class BaseDigestCalculator
    implements IntDigestCalculator
{
    private final byte[] digest;

    BaseDigestCalculator(byte[] digest)
    {
        this.digest = digest;
    }

    public byte[] getDigest()
    {
        return Arrays.clone(digest);
    }
}
