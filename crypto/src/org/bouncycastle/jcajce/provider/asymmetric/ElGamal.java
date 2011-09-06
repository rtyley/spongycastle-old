package org.bouncycastle.jcajce.provider.asymmetric;

import java.util.HashMap;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.elgamal.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.asymmetric.util.BCKeyFactory;

public class ElGamal
{
    private static final String PREFIX = ElGamal.class.getPackage().getName() + ".elgamal.";

    public static class Mappings
        extends HashMap
    {
        public Mappings()
        {
            put("AlgorithmParameterGenerator.ELGAMAL", PREFIX + "AlgorithmParameterGeneratorSpi");
            put("AlgorithmParameters.ELGAMAL", PREFIX + "AlgorithmParametersSpi");

            put("Cipher.ELGAMAL", PREFIX + "CipherSpi$NoPadding");
            put("Cipher.ELGAMAL/PKCS1", PREFIX + "CipherSpi$PKCS1v1_5Padding");
            put("KeyFactory.ELGAMAL", PREFIX + "KeyFactorySpi");
            put("KeyFactory.ElGamal", PREFIX + "KeyFactorySpi");

            put("KeyPairGenerator.ELGAMAL", PREFIX + "KeyPairGeneratorSpi");

            BCKeyFactory keyFact = new KeyFactorySpi();

            registerOid(OIWObjectIdentifiers.elGamalAlgorithm, keyFact);
        }

        private void registerOid(ASN1ObjectIdentifier oid, BCKeyFactory keyFactory)
        {
            put("Alg.Alias.KeyPairGenerator." + oid, "ELGAMAL");
            put("Alg.Alias.KeyFactory." + oid, "ELGAMAL");
            put("Alg.Alias.AlgorithmParameters." + oid, "ELGAMAL");
            put("Alg.Alias.AlgorithmParameterGenerator." + oid, "ELGAMAL");

            X509.registerKeyFactory(oid, keyFactory);
        }
    }
}
