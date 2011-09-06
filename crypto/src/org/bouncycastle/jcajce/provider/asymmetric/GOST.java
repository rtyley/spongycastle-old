package org.bouncycastle.jcajce.provider.asymmetric;

import java.util.HashMap;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.gost.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.asymmetric.util.BCKeyFactory;

public class GOST
{
    private static final String PREFIX = GOST.class.getPackage().getName() + ".gost.";

    public static class Mappings
        extends HashMap
    {
        public Mappings()
        {
            put("KeyPairGenerator.GOST3410", PREFIX + "KeyPairGeneratorSpi");
            put("Alg.Alias.KeyPairGenerator.GOST-3410", "GOST3410");
            put("Alg.Alias.KeyPairGenerator.GOST-3410-94", "GOST3410");

            put("KeyFactory.GOST3410", PREFIX + "KeyFactorySpi");
            put("Alg.Alias.KeyFactory.GOST-3410", "GOST3410");
            put("Alg.Alias.KeyFactory.GOST-3410-94", "GOST3410");

            addKeyFactory("GOST3410", CryptoProObjectIdentifiers.gostR3410_94, new KeyFactorySpi());

            put("Signature.GOST3410", PREFIX + "SignatureSpi");
            put("Alg.Alias.Signature.GOST-3410", "GOST3410");
            put("Alg.Alias.Signature.GOST-3410-94", "GOST3410");
            put("Alg.Alias.Signature.GOST3411withGOST3410", "GOST3410");
            put("Alg.Alias.Signature.GOST3411WITHGOST3410", "GOST3410");
            put("Alg.Alias.Signature.GOST3411WithGOST3410", "GOST3410");
            put("Alg.Alias.Signature." + CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94, "GOST3410");
        }

        private void addSignatureAlgorithm(
            String digest,
            String algorithm,
            String className,
            ASN1ObjectIdentifier oid)
        {
            String mainName = digest + "WITH" + algorithm;
            String jdk11Variation1 = digest + "with" + algorithm;
            String jdk11Variation2 = digest + "With" + algorithm;
            String alias = digest + "/" + algorithm;

            put("Signature." + mainName, className);
            put("Alg.Alias.Signature." + jdk11Variation1, mainName);
            put("Alg.Alias.Signature." + jdk11Variation2, mainName);
            put("Alg.Alias.Signature." + alias, mainName);
            put("Alg.Alias.Signature." + oid, mainName);
            put("Alg.Alias.Signature.OID." + oid, mainName);
        }

        private void addKeyFactory(String name, ASN1ObjectIdentifier oid, BCKeyFactory keyFactory)
        {
            put("Alg.Alias.KeyFactory." + oid, name);
            X509.registerKeyFactory(oid, keyFactory);
        }
    }
}
