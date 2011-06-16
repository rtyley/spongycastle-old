package org.bouncycastle.openpgp;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;

public abstract class PBEDataDecryptorFactory
    implements PGPDataDecryptorFactory
{
    private char[] passPhrase;
    private PGPDigestCalculatorProvider calculatorProvider;

    protected PBEDataDecryptorFactory(char[] passPhrase, PGPDigestCalculatorProvider calculatorProvider)
    {
        this.passPhrase = passPhrase;
        this.calculatorProvider = calculatorProvider;
    }

    byte[] makeKeyFromPassPhrase(int keyAlgorithm, S2K s2k)
        throws PGPException
    {
        return PGPUtil.makeKeyFromPassPhrase(calculatorProvider, keyAlgorithm, s2k, passPhrase);
    }

    public abstract byte[] recoverSessionData(int keyAlgorithm, byte[] key, byte[] seckKeyData)
        throws PGPException;
}
