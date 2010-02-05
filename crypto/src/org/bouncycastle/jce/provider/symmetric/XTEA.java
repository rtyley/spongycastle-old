package org.bouncycastle.jce.provider.symmetric;

import java.util.HashMap;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.engines.XTEAEngine;
import org.bouncycastle.jce.provider.JCEBlockCipher;
import org.bouncycastle.jce.provider.JCEKeyGenerator;
import org.bouncycastle.jce.provider.JDKAlgorithmParameters;

public final class XTEA
{
    private XTEA()
    {
    }
    
    public static class ECB
        extends JCEBlockCipher
    {
        public ECB()
        {
            super(new XTEAEngine());
        }
    }

    public static class KeyGen
        extends JCEKeyGenerator
    {
        public KeyGen()
        {
            super("XTEA", 128, new CipherKeyGenerator());
        }
    }

    public static class AlgParams
        extends JDKAlgorithmParameters.IVAlgorithmParameters
    {
        protected String engineToString()
        {
            return "XTEA IV";
        }
    }

    public static class Mappings
        extends HashMap
    {
        public Mappings()
        {
            put("Cipher.XTEA", "org.bouncycastle.jce.provider.symmetric.XTEA$ECB");
            put("KeyGenerator.XTEA", "org.bouncycastle.jce.provider.symmetric.XTEA$KeyGen");
            put("AlgorithmParameters.XTEA", "org.bouncycastle.jce.provider.symmetric.XTEA$AlgParams");
        }
    }
}
