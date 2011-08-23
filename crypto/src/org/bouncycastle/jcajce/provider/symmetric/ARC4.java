package org.bouncycastle.jcajce.provider.symmetric;

import java.util.HashMap;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher;

public final class ARC4
{
    private ARC4()
    {
    }
    
    public static class Base
        extends BaseStreamCipher
    {
        public Base()
        {
            super(new RC4Engine(), 0);
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("RC4", 128, new CipherKeyGenerator());
        }
    }

    public static class Mappings
        extends HashMap
    {
        private static final String PREFIX = ARC4.class.getName();

        public Mappings()
        {
            put("Cipher.ARC4", PREFIX + "$Base");
            put("Alg.Alias.Cipher.1.2.840.113549.3.4", "ARC4");
            put("Alg.Alias.Cipher.ARCFOUR", "ARC4");
            put("Alg.Alias.Cipher.RC4", "ARC4");
            put("KeyGenerator.ARC4", PREFIX + "$KeyGen");
            put("Alg.Alias.KeyGenerator.RC4", "ARC4");
            put("Alg.Alias.KeyGenerator.1.2.840.113549.3.4", "ARC4");
        }
    }
}
