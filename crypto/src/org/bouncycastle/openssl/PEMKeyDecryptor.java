package org.bouncycastle.openssl;

public interface PEMKeyDecryptor
{
    byte[] recoverKeyData(byte[] keyBytes, byte[] iv)
        throws PEMException;
}
