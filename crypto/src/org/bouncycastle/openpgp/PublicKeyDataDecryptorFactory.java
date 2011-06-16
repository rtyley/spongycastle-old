package org.bouncycastle.openpgp;

import java.math.BigInteger;

public interface PublicKeyDataDecryptorFactory
    extends PGPDataDecryptorFactory
{
    public byte[] recoverSessionData(int keyAlgorithm, BigInteger[] secKeyData)
            throws PGPException;
}
