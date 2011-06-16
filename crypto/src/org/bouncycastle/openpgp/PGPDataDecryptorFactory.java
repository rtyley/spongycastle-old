package org.bouncycastle.openpgp;

import org.bouncycastle.openpgp.operator.PGPDataDecryptor;

public interface PGPDataDecryptorFactory
{
    public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
        throws PGPException;
}
