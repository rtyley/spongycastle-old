package org.spongycastle.cms;

import java.security.NoSuchAlgorithmException;

interface IntDigestCalculator
{
    byte[] getDigest()
        throws NoSuchAlgorithmException;
}
