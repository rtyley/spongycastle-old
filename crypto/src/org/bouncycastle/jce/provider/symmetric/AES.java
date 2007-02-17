package org.bouncycastle.jce.provider.symmetric;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.AESWrapEngine;
import org.bouncycastle.crypto.engines.RFC3211WrapEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.jce.provider.JCEBlockCipher;
import org.bouncycastle.jce.provider.JCEKeyGenerator;
import org.bouncycastle.jce.provider.WrapCipherSpi;

public class AES
{
    public static class ECB
        extends JCEBlockCipher
    {
        public ECB()
        {
            super(new AESFastEngine());
        }
    }

    public static class CBC
       extends JCEBlockCipher
    {
        public CBC()
        {
            super(new CBCBlockCipher(new AESFastEngine()), 128);
        }
    }

    static public class CFB
        extends JCEBlockCipher
    {
        public CFB()
        {
            super(new CFBBlockCipher(new AESFastEngine(), 128), 128);
        }
    }

    static public class OFB
        extends JCEBlockCipher
    {
        public OFB()
        {
            super(new OFBBlockCipher(new AESFastEngine(), 128), 128);
        }
    }

    static public class Wrap
        extends WrapCipherSpi
    {
        public Wrap()
        {
            super(new AESWrapEngine());
        }
    }

    public static class RFC3211Wrap
        extends WrapCipherSpi
    {
        public RFC3211Wrap()
        {
            super(new RFC3211WrapEngine(new AESEngine()), 16);
        }
    }

    public static class KeyGen
        extends JCEKeyGenerator
    {
        public KeyGen()
        {
            this(192);
        }

        public KeyGen(int keySize)
        {
            super("AES", keySize, new CipherKeyGenerator());
        }
    }

    public static class KeyGen128
        extends KeyGen
    {
        public KeyGen128()
        {
            super(128);
        }
    }

    public static class KeyGen192
        extends KeyGen
    {
        public KeyGen192()
        {
            super(192);
        }
    }

    public static class KeyGen256
        extends KeyGen
    {
        public KeyGen256()
        {
            super(256);
        }
    }
}
