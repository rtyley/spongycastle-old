package org.bouncycastle.jcajce.provider.symmetric;

import java.util.HashMap;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.engines.RC2WrapEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseWrapCipher;

public final class RC2
{
    private RC2()
    {
    }

    /**
     * RC2
     */
    static public class ECB
        extends BaseBlockCipher
    {
        public ECB()
        {
            super(new RC2Engine());
        }
    }

    /**
     * RC2CBC
     */
    static public class CBC
        extends BaseBlockCipher
    {
        public CBC()
        {
            super(new CBCBlockCipher(new RC2Engine()), 64);
        }
    }

    public static class Wrap
        extends BaseWrapCipher
    {
        public Wrap()
        {
            super(new RC2WrapEngine());
        }
    }

    public static class Mappings
        extends HashMap
    {
        private static final String PREFIX = RC2.class.getName();
                 
        public Mappings()
        {
            put("AlgorithmParameterGenerator.RC2", PREFIX + "$RC2");
            put("AlgorithmParameterGenerator.1.2.840.113549.3.2", PREFIX + "$RC2");

            put("Cipher.RC2", PREFIX + "$ECB");
            put("Cipher.RC2WRAP", PREFIX + "$Wrap");
            put("Alg.Alias.Cipher." + PKCSObjectIdentifiers.id_alg_CMSRC2wrap, "RC2WRAP");

            put("Cipher.1.2.840.113549.3.2", PREFIX + "$CBC");
        }
    }
}
