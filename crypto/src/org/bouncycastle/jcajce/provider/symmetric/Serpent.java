package org.bouncycastle.jcajce.provider.symmetric;

import java.util.HashMap;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.engines.SerpentEngine;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;

public final class Serpent
{
    private Serpent()
    {
    }
    
    public static class ECB
        extends BaseBlockCipher
    {
        public ECB()
        {
            super(new SerpentEngine());
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("Serpent", 192, new CipherKeyGenerator());
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Serpent IV";
        }
    }

    public static class Mappings
        extends HashMap
    {
        private static final String PREFIX = Serpent.class.getName();
                 
        public Mappings()
        {
            put("Cipher.Serpent", PREFIX + "$ECB");
            put("KeyGenerator.Serpent", PREFIX + "$KeyGen");
            put("AlgorithmParameters.Serpent", PREFIX + "$AlgParams");
        }
    }
}
