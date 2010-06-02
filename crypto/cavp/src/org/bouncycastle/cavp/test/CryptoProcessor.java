package org.bouncycastle.cavp.test;

import java.security.GeneralSecurityException;

public interface CryptoProcessor
{
    void init(byte[] key)
        throws GeneralSecurityException;

    void init(byte[] key, byte[] iv)
        throws GeneralSecurityException;

    byte[] process(byte[] in)
        throws GeneralSecurityException;
}
