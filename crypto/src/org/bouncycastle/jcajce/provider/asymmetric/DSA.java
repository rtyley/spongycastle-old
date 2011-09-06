package org.bouncycastle.jcajce.provider.asymmetric;

import java.util.HashMap;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.asymmetric.util.BCKeyFactory;

public class DSA
{
    private static final String PREFIX = DSA.class.getPackage().getName() + ".dsa.";

    public static class Mappings
        extends HashMap
    {
        public Mappings()
        {
            put("AlgorithmParameterGenerator.DSA", "org.bouncycastle.jcajce.provider.asymmetric.dsa.AlgorithmParameterGenerator");

            put("KeyPairGenerator.DSA", PREFIX + "KeyPairGeneratorSpi");
            put("KeyFactory.DSA", PREFIX + "KeyFactorySpi");

            put("Signature.DSA", "org.bouncycastle.jcajce.provider.asymmetric.dsa.DSASigner$stdDSA");
            put("Signature.NONEWITHDSA", "org.bouncycastle.jcajce.provider.asymmetric.dsa.DSASigner$noneDSA");

            put("Alg.Alias.Signature.RAWDSA", "NONEWITHDSA");

            addSignatureAlgorithm("SHA224", "org.bouncycastle.jcajce.provider.dsa.DSASigner$dsa224", NISTObjectIdentifiers.dsa_with_sha224);
            addSignatureAlgorithm("SHA256", "org.bouncycastle.jcajce.provider.dsa.DSASigner$dsa256", NISTObjectIdentifiers.dsa_with_sha256);
            addSignatureAlgorithm("SHA384", "org.bouncycastle.jcajce.provider.dsa.DSASigner$dsa384", NISTObjectIdentifiers.dsa_with_sha384);
            addSignatureAlgorithm("SHA512", "org.bouncycastle.jcajce.provider.dsa.DSASigner$dsa512", NISTObjectIdentifiers.dsa_with_sha512);

            put("Alg.Alias.Signature.SHA/DSA", "DSA");
            put("Alg.Alias.Signature.SHA1withDSA", "DSA");
            put("Alg.Alias.Signature.SHA1WITHDSA", "DSA");
            put("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.10040.4.1", "DSA");
            put("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.10040.4.3", "DSA");
            put("Alg.Alias.Signature.DSAwithSHA1", "DSA");
            put("Alg.Alias.Signature.DSAWITHSHA1", "DSA");
            put("Alg.Alias.Signature.SHA1WithDSA", "DSA");
            put("Alg.Alias.Signature.DSAWithSHA1", "DSA");
            put("Alg.Alias.Signature.1.2.840.10040.4.3", "DSA");

            BCKeyFactory keyFact = new KeyFactorySpi();

            for (int i = 0; i != DSAUtil.dsaOids.length; i++)
            {
                registerOid(DSAUtil.dsaOids[i], keyFact);
            }
        }

        private void addSignatureAlgorithm(
            String digest,
            String className,
            ASN1ObjectIdentifier oid)
        {
            String mainName = digest + "WITHDSA";
            String jdk11Variation1 = digest + "withDSA";
            String jdk11Variation2 = digest + "WithDSA";
            String alias = digest + "/" + "DSA";

            put("Signature." + mainName, className);
            put("Alg.Alias.Signature." + jdk11Variation1, mainName);
            put("Alg.Alias.Signature." + jdk11Variation2, mainName);
            put("Alg.Alias.Signature." + alias, mainName);
            put("Alg.Alias.Signature." + oid, mainName);
            put("Alg.Alias.Signature.OID." + oid, mainName);
        }

        private void registerOid(ASN1ObjectIdentifier oid, BCKeyFactory keyFactory)
        {
            put("Alg.Alias.KeyPairGenerator." + oid, "DSA");
            put("Alg.Alias.KeyFactory." + oid, "DSA");
            put("Alg.Alias.AlgorithmParameters." + oid, "DSA");
            put("Alg.Alias.AlgorithmParameterGenerator." + oid, "DSA");

            X509.registerKeyFactory(oid, keyFactory);
        }
    }
}
