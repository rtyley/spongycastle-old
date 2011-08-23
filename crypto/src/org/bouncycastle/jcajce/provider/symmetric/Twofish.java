package org.bouncycastle.jcajce.provider.symmetric;

import java.util.HashMap;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;

public final class Twofish
{
    private Twofish()
    {
    }
    
    public static class ECB
        extends BaseBlockCipher
    {
        public ECB()
        {
            super(new TwofishEngine());
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("Twofish", 256, new CipherKeyGenerator());
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Twofish IV";
        }
    }

    public static class Mappings
        extends HashMap
    {
        private static final String PREFIX = Twofish.class.getName();
                 
        public Mappings()
        {
            put("Cipher.Twofish", PREFIX + "$ECB");
            put("KeyGenerator.Twofish", PREFIX + "$KeyGen");
            put("AlgorithmParameters.Twofish", PREFIX + "$AlgParams");
        }
    }
}
