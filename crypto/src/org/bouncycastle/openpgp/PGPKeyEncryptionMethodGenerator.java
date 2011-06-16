package org.bouncycastle.openpgp;

import org.bouncycastle.bcpg.ContainedPacket;

public abstract class PGPKeyEncryptionMethodGenerator
{
    public abstract ContainedPacket generate(int encAlgorithm, byte[] sessionInfo)
        throws PGPException;
}
