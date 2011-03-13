package org.spongycastle.jce.provider.symmetric;

import java.util.HashMap;

import org.spongycastle.crypto.CipherKeyGenerator;
import org.spongycastle.crypto.engines.CAST6Engine;
import org.spongycastle.jce.provider.JCEBlockCipher;
import org.spongycastle.jce.provider.JCEKeyGenerator;

public final class CAST6
{
    private CAST6()
    {
    }
    
    public static class ECB
        extends JCEBlockCipher
    {
        public ECB()
        {
            super(new CAST6Engine());
        }
    }

    public static class KeyGen
        extends JCEKeyGenerator
    {
        public KeyGen()
        {
            super("CAST6", 256, new CipherKeyGenerator());
        }
    }

    public static class Mappings
        extends HashMap
    {
        public Mappings()
        {
            put("Cipher.CAST6", "org.spongycastle.jce.provider.symmetric.CAST6$ECB");
            put("KeyGenerator.CAST6", "org.spongycastle.jce.provider.symmetric.CAST6$KeyGen");
        }
    }
}
