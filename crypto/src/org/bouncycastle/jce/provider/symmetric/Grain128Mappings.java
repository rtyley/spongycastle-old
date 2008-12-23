package org.bouncycastle.jce.provider.symmetric;

import java.util.HashMap;

public class Grain128Mappings
    extends HashMap
{
    public Grain128Mappings()
    {
        put("Cipher.Grain128", "org.bouncycastle.jce.provider.symmetric.Grain128$Base");
        put("KeyGenerator.Grain128", "org.bouncycastle.jce.provider.symmetric.Grain128$KeyGen");
    }
}
