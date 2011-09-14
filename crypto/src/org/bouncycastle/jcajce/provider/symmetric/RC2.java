package org.bouncycastle.jcajce.provider.symmetric;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.engines.RC2WrapEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseWrapCipher;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;
import org.bouncycastle.jce.interfaces.ConfigurableProvider;

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
        extends AlgorithmProvider
    {
        private static final String PREFIX = RC2.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {

            provider.addAlgorithm("AlgorithmParameterGenerator.RC2", PREFIX + "$RC2");
            provider.addAlgorithm("AlgorithmParameterGenerator.1.2.840.113549.3.2", PREFIX + "$RC2");

            provider.addAlgorithm("Cipher.RC2", PREFIX + "$ECB");
            provider.addAlgorithm("Cipher.RC2WRAP", PREFIX + "$Wrap");
            provider.addAlgorithm("Alg.Alias.Cipher." + PKCSObjectIdentifiers.id_alg_CMSRC2wrap, "RC2WRAP");

            provider.addAlgorithm("Cipher.1.2.840.113549.3.2", PREFIX + "$CBC");

        }
    }
}
