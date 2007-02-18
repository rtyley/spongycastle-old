package org.bouncycastle.jce.provider.symmetric;

import java.util.HashMap;

public class CAST5Mappings
    extends HashMap
{
    public CAST5Mappings()
    {
        put("AlgorithmParameters.CAST5", "org.bouncycastle.jce.provider.symmetric.CAST5$AlgParams");
        put("Alg.Alias.AlgorithmParameters.1.2.840.113533.7.66.10", "CAST5");

        put("AlgorithmParameterGenerator.CAST5", "org.bouncycastle.jce.provider.symmetric.CAST5$AlgParamGen");
        put("Alg.Alias.AlgorithmParameterGenerator.1.2.840.113533.7.66.10", "CAST5");

        put("Cipher.CAST5", "org.bouncycastle.jce.provider.symmetric.CAST5$ECB");
        put("Cipher.1.2.840.113533.7.66.10", "org.bouncycastle.jce.provider.symmetric.CAST5$CBC");

        put("KeyGenerator.CAST5", "org.bouncycastle.jce.provider.symmetric.CAST5$KeyGen");
        put("Alg.Alias.KeyGenerator.1.2.840.113533.7.66.10", "CAST5");
    }
}
