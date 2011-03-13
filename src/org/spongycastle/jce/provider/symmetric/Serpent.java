package org.spongycastle.jce.provider.symmetric;

import java.util.HashMap;

import org.spongycastle.crypto.CipherKeyGenerator;
import org.spongycastle.crypto.engines.SerpentEngine;
import org.spongycastle.jce.provider.JCEBlockCipher;
import org.spongycastle.jce.provider.JCEKeyGenerator;
import org.spongycastle.jce.provider.JDKAlgorithmParameters;

public final class Serpent
{
    private Serpent()
    {
    }
    
    public static class ECB
        extends JCEBlockCipher
    {
        public ECB()
        {
            super(new SerpentEngine());
        }
    }

    public static class KeyGen
        extends JCEKeyGenerator
    {
        public KeyGen()
        {
            super("Serpent", 192, new CipherKeyGenerator());
        }
    }

    public static class AlgParams
        extends JDKAlgorithmParameters.IVAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Serpent IV";
        }
    }

    public static class Mappings
        extends HashMap
    {
        public Mappings()
        {
            put("Cipher.Serpent", "org.spongycastle.jce.provider.symmetric.Serpent$ECB");
            put("KeyGenerator.Serpent", "org.spongycastle.jce.provider.symmetric.Serpent$KeyGen");
            put("AlgorithmParameters.Serpent", "org.spongycastle.jce.provider.symmetric.Serpent$AlgParams");
        }
    }
}
