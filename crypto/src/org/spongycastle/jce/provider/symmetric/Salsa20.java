package org.spongycastle.jce.provider.symmetric;

import java.util.HashMap;

import org.spongycastle.crypto.CipherKeyGenerator;
import org.spongycastle.crypto.engines.Salsa20Engine;
import org.spongycastle.jce.provider.JCEKeyGenerator;
import org.spongycastle.jce.provider.JCEStreamCipher;

public final class Salsa20
{
    private Salsa20()
    {
    }
    
    public static class Base
        extends JCEStreamCipher
    {
        public Base()
        {
            super(new Salsa20Engine(), 8);
        }
    }

    public static class KeyGen
        extends JCEKeyGenerator
    {
        public KeyGen()
        {
            super("Salsa20", 128, new CipherKeyGenerator());
        }
    }

    public static class Mappings
        extends HashMap
    {
        public Mappings()
        {
            put("Cipher.SALSA20", "org.spongycastle.jce.provider.symmetric.Salsa20$Base");
            put("KeyGenerator.SALSA20", "org.spongycastle.jce.provider.symmetric.Salsa20$KeyGen");
        }
    }
}
