package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;

public class McEliece
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".mceliece.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            // McElieceKobaraImai
            provider.addAlgorithm("KeyPairGenerator.McElieceKobaraImai", PREFIX + "McElieceKeyPairGeneratorSpi$McElieceCCA2");
            // McEliecePointcheval
            provider.addAlgorithm("KeyPairGenerator.McEliecePointcheval", PREFIX + "McElieceKeyPairGeneratorSpi$McElieceCCA2");
            // McElieceFujisaki
            provider.addAlgorithm("KeyPairGenerator.McElieceFujisaki", PREFIX + "McElieceKeyPairGeneratorSpi$McElieceCCA2");
            // McEliecePKCS
            provider.addAlgorithm("KeyPairGenerator.McEliecePKCS", PREFIX + "McElieceKeyPairGeneratorSpi$McEliece");

            provider.addAlgorithm("KeyPairGenerator." + PQCObjectIdentifiers.mcEliece, PREFIX + "McElieceKeyPairGeneratorSpi$McEliece");
            provider.addAlgorithm("KeyPairGenerator." + PQCObjectIdentifiers.mcElieceCca2, PREFIX + "McElieceKeyPairGeneratorSpi$McElieceCCA2");
        }
    }
}
