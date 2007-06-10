package org.bouncycastle.jce.provider.symmetric;

import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;

import java.util.HashMap;

public class NoekeonMappings
    extends HashMap
{
    public NoekeonMappings()
    {
        put("AlgorithmParameters.NOEKEON", "org.bouncycastle.jce.provider.symmetric.Noekeon$AlgParams");

        put("AlgorithmParameterGenerator.NOEKEON", "org.bouncycastle.jce.provider.symmetric.Noekeon$AlgParamGen");
        
        put("Cipher.NOEKEON", "org.bouncycastle.jce.provider.symmetric.Noekeon$ECB");

        put("KeyGenerator.NOEKEON", "org.bouncycastle.jce.provider.symmetric.Noekeon$KeyGen");
    }
}
