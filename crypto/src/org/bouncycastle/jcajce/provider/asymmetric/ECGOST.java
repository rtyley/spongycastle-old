package org.bouncycastle.jcajce.provider.asymmetric;

import java.util.HashMap;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.asymmetric.util.BCKeyFactory;

public class ECGOST
{
    private static final String PREFIX = ECGOST.class.getPackage().getName() + ".ecgost.";

    public static class Mappings
        extends HashMap
    {
        public Mappings()
        {
            put("KeyFactory.ECGOST3410", PREFIX + "KeyFactorySpi");
            put("Alg.Alias.KeyFactory.GOST-3410-2001", "ECGOST3410");
            put("Alg.Alias.KeyFactory.ECGOST-3410", "ECGOST3410");

            registerOid(CryptoProObjectIdentifiers.gostR3410_2001, "ECGOST3410", new KeyFactorySpi());

            put("KeyPairGenerator.ECGOST3410", PREFIX + "KeyPairGeneratorSpi");
            put("Alg.Alias.KeyPairGenerator.ECGOST-3410", "ECGOST3410");
            put("Alg.Alias.KeyPairGenerator.GOST-3410-2001", "ECGOST3410");

            put("Signature.ECGOST3410", PREFIX + "SignatureSpi");
            put("Alg.Alias.Signature.ECGOST-3410", "ECGOST3410");
            put("Alg.Alias.Signature.GOST-3410-2001", "ECGOST3410");

            addSignatureAlgorithm("GOST3411", "ECGOST3410", PREFIX + "SignatureSpi", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);
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

        private void registerOid(ASN1ObjectIdentifier oid, String name, BCKeyFactory keyFactory)
        {
            put("Alg.Alias.KeyFactory." + oid, name);
            put("Alg.Alias.KeyPairGenerator." + oid, name);

            X509.registerKeyFactory(oid, keyFactory);
        }
    }
}
