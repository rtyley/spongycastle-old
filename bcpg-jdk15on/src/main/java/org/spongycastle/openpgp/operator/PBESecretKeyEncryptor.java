package org.spongycastle.openpgp.operator;

import java.security.SecureRandom;

import org.spongycastle.bcpg.S2K;
import org.spongycastle.openpgp.PGPException;

public abstract class PBESecretKeyEncryptor
{
    protected int encAlgorithm;
    protected char[] passPhrase;
    protected PGPDigestCalculator s2kDigestCalculator;
    protected S2K s2k;

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
