package org.bouncycastle.cms;

import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;

interface DigestCalculator
{
    byte[] getDigest()
        throws NoSuchProviderException, NoSuchAlgorithmException;
}
