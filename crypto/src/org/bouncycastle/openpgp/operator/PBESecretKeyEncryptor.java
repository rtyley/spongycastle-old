package org.bouncycastle.openpgp.operator;

import java.security.SecureRandom;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.openpgp.PGPException;

public abstract class PBESecretKeyEncryptor
{
    private int encAlgorithm;
    private char[] passPhrase;
    private PGPDigestCalculator s2kDigestCalculator;
    private S2K s2k;

    protected SecureRandom random;

    protected PBESecretKeyEncryptor(int encAlgorithm, PGPDigestCalculator s2kDigestCalculator, SecureRandom random, char[] passPhrase)
    {
        this.encAlgorithm = encAlgorithm;
        this.passPhrase = passPhrase;
        this.random = random;
        this.s2kDigestCalculator = s2kDigestCalculator;
    }

    public int getAlgorithm()
    {
        return encAlgorithm;
    }

    public byte[] getKey()
        throws PGPException
    {
        if (s2k == null)
        {
            byte[]        iv = new byte[8];

            random.nextBytes(iv);

            s2k = new S2K(s2kDigestCalculator.getAlgorithm(), iv, 0x60);
        }

        return PGPUtil.makeKeyFromPassPhrase(s2kDigestCalculator, encAlgorithm, s2k, passPhrase);
    }

    public S2K getS2K()
    {
        return s2k;
    }

    public byte[] encryptKeyData(byte[] keyData, int keyOff, int keyLen)
        throws PGPException
    {
        return encryptKeyData(getKey(), keyData, keyOff, keyLen);
    }

    public abstract byte[] encryptKeyData(byte[] key, byte[] keyData, int keyOff, int keyLen)
        throws PGPException;

    public abstract byte[] getCipherIV();
}
