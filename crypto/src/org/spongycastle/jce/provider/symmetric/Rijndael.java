package org.spongycastle.jce.provider.symmetric;

import java.util.HashMap;

import org.spongycastle.crypto.CipherKeyGenerator;
import org.spongycastle.crypto.engines.RijndaelEngine;
import org.spongycastle.jce.provider.JCEBlockCipher;
import org.spongycastle.jce.provider.JCEKeyGenerator;
import org.spongycastle.jce.provider.JDKAlgorithmParameters;

public final class Rijndael
{
    private Rijndael()
    {
    }
    
    public static class ECB
        extends JCEBlockCipher
    {
        public ECB()
        {
            super(new RijndaelEngine());
        }
    }

    public static class KeyGen
        extends JCEKeyGenerator
    {
        public KeyGen()
        {
            super("Rijndael", 192, new CipherKeyGenerator());
        }
    }

    public static class AlgParams
        extends JDKAlgorithmParameters.IVAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Rijndael IV";
        }
    }

    public static class Mappings
        extends HashMap
    {
        public Mappings()
        {
            put("Cipher.RIJNDAEL", "org.spongycastle.jce.provider.symmetric.Rijndael$ECB");
            put("KeyGenerator.RIJNDAEL", "org.spongycastle.jce.provider.symmetric.Rijndael$KeyGen");
            put("AlgorithmParameters.RIJNDAEL", "org.spongycastle.jce.provider.symmetric.Rijndael$AlgParams");
        }
    }
}
