package org.spongycastle.jce.provider.symmetric;

import java.util.HashMap;

import org.spongycastle.crypto.CipherKeyGenerator;
import org.spongycastle.crypto.engines.TEAEngine;
import org.spongycastle.jce.provider.JCEBlockCipher;
import org.spongycastle.jce.provider.JCEKeyGenerator;
import org.spongycastle.jce.provider.JDKAlgorithmParameters;

public final class TEA
{
    private TEA()
    {
    }
    
    public static class ECB
        extends JCEBlockCipher
    {
        public ECB()
        {
            super(new TEAEngine());
        }
    }

    public static class KeyGen
        extends JCEKeyGenerator
    {
        public KeyGen()
        {
            super("TEA", 128, new CipherKeyGenerator());
        }
    }

    public static class AlgParams
        extends JDKAlgorithmParameters.IVAlgorithmParameters
    {
        protected String engineToString()
        {
            return "TEA IV";
        }
    }

    public static class Mappings
        extends HashMap
    {
        public Mappings()
        {
            put("Cipher.TEA", "org.spongycastle.jce.provider.symmetric.TEA$ECB");
            put("KeyGenerator.TEA", "org.spongycastle.jce.provider.symmetric.TEA$KeyGen");
            put("AlgorithmParameters.TEA", "org.spongycastle.jce.provider.symmetric.TEA$AlgParams");
        }
    }
}
