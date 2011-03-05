package org.spongycastle.jce.provider.symmetric;

import java.util.HashMap;

import org.spongycastle.crypto.CipherKeyGenerator;
import org.spongycastle.crypto.engines.VMPCEngine;
import org.spongycastle.crypto.macs.VMPCMac;
import org.spongycastle.jce.provider.JCEKeyGenerator;
import org.spongycastle.jce.provider.JCEMac;
import org.spongycastle.jce.provider.JCEStreamCipher;

public final class VMPC
{
    private VMPC()
    {
    }
    
    public static class Base
        extends JCEStreamCipher
    {
        public Base()
        {
            super(new VMPCEngine(), 16);
        }
    }

    public static class KeyGen
        extends JCEKeyGenerator
    {
        public KeyGen()
        {
            super("VMPC", 128, new CipherKeyGenerator());
        }
    }

    public static class Mac
        extends JCEMac
    {
        public Mac()
        {
            super(new VMPCMac());
        }
    }

    public static class Mappings
        extends HashMap
    {
        public Mappings()
        {
            put("Cipher.VMPC", "org.spongycastle.jce.provider.symmetric.VMPC$Base");
            put("KeyGenerator.VMPC", "org.spongycastle.jce.provider.symmetric.VMPC$KeyGen");
            put("Mac.VMPCMAC", "org.spongycastle.jce.provider.symmetric.VMPC$Mac");
            put("Alg.Alias.Mac.VMPC", "VMPCMAC");
            put("Alg.Alias.Mac.VMPC-MAC", "VMPCMAC");
        }
    }
}
