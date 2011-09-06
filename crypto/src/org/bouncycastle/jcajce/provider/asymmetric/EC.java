package org.bouncycastle.jcajce.provider.asymmetric;

import java.util.HashMap;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.asymmetric.util.BCKeyFactory;

public class EC
{
    private static final String PREFIX = EC.class.getPackage().getName() + ".ec.";

    public static class Mappings
        extends HashMap
    {
        public Mappings()
        {
            put("KeyAgreement.ECDH", PREFIX + "KeyAgreementSpi$DH");
            put("KeyAgreement.ECDHC", PREFIX + "KeyAgreementSpi$DHC");
            put("KeyAgreement.ECMQV", PREFIX + "KeyAgreementSpi$MQV");
            put("KeyAgreement." + X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme, PREFIX + "KeyAgreementSpi$DHwithSHA1KDF");
            put("KeyAgreement." + X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme, PREFIX + "KeyAgreementSpi$MQVwithSHA1KDF");

            registerOid(X9ObjectIdentifiers.id_ecPublicKey, "EC", new KeyFactorySpi.EC());
            // TODO Should this be an alias for ECDH?
            registerOid(X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme, "EC", new KeyFactorySpi.EC());
            registerOid(X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme, "ECMQV", new KeyFactorySpi.ECMQV());

            put("KeyFactory.EC", PREFIX + "KeyFactorySpi$EC");
            put("KeyFactory.ECDSA", PREFIX + "KeyFactorySpi$ECDSA");
            put("KeyFactory.ECDH", PREFIX + "KeyFactorySpi$ECDH");
            put("KeyFactory.ECDHC", PREFIX + "KeyFactorySpi$ECDHC");
            put("KeyFactory.ECMQV", PREFIX + "KeyFactorySpi$ECMQV");

            put("KeyPairGenerator.EC", PREFIX + "KeyPairGeneratorSpi$EC");
            put("KeyPairGenerator.ECDSA", PREFIX + "KeyPairGeneratorSpi$ECDSA");
            put("KeyPairGenerator.ECDH", PREFIX + "KeyPairGeneratorSpi$ECDH");
            put("KeyPairGenerator.ECDHC", PREFIX + "KeyPairGeneratorSpi$ECDHC");
            put("KeyPairGenerator.ECIES", PREFIX + "KeyPairGeneratorSpi$ECDH");
            put("KeyPairGenerator.ECMQV", PREFIX + "KeyPairGeneratorSpi$ECMQV");
            // TODO Should this be an alias for ECDH?
            put("Alg.Alias.KeyPairGenerator." + X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme, "EC");
            put("Alg.Alias.KeyPairGenerator." + X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme, "ECMQV");

            put("Signature.ECDSA", PREFIX + "SignatureSpi$ecDSA");
            put("Signature.NONEwithECDSA", PREFIX + "SignatureSpi$ecDSAnone");

            put("Alg.Alias.Signature.SHA1withECDSA", "ECDSA");
            put("Alg.Alias.Signature.ECDSAwithSHA1", "ECDSA");
            put("Alg.Alias.Signature.SHA1WITHECDSA", "ECDSA");
            put("Alg.Alias.Signature.ECDSAWITHSHA1", "ECDSA");
            put("Alg.Alias.Signature.SHA1WithECDSA", "ECDSA");
            put("Alg.Alias.Signature.ECDSAWithSHA1", "ECDSA");
            put("Alg.Alias.Signature.1.2.840.10045.4.1", "ECDSA");
            put("Alg.Alias.Signature." + TeleTrusTObjectIdentifiers.ecSignWithSha1, "ECDSA");

            addSignatureAlgorithm("SHA224", "ECDSA", PREFIX + "SignatureSpi$ecDSA224", X9ObjectIdentifiers.ecdsa_with_SHA224);
            addSignatureAlgorithm("SHA256", "ECDSA", PREFIX + "SignatureSpi$ecDSA256", X9ObjectIdentifiers.ecdsa_with_SHA256);
            addSignatureAlgorithm("SHA384", "ECDSA", PREFIX + "SignatureSpi$ecDSA384", X9ObjectIdentifiers.ecdsa_with_SHA384);
            addSignatureAlgorithm("SHA512", "ECDSA", PREFIX + "SignatureSpi$ecDSA512", X9ObjectIdentifiers.ecdsa_with_SHA512);
            addSignatureAlgorithm("RIPEMD160", "ECDSA", PREFIX + "SignatureSpi$ecDSARipeMD160",TeleTrusTObjectIdentifiers.ecSignWithRipemd160);

            put("Signature.SHA1WITHECNR", PREFIX + "SignatureSpi$ecNR");
            put("Signature.SHA224WITHECNR", PREFIX + "SignatureSpi$ecNR224");
            put("Signature.SHA256WITHECNR", PREFIX + "SignatureSpi$ecNR256");
            put("Signature.SHA384WITHECNR", PREFIX + "SignatureSpi$ecNR384");
            put("Signature.SHA512WITHECNR", PREFIX + "SignatureSpi$ecNR512");

            addSignatureAlgorithm("SHA1", "CVC-ECDSA", PREFIX + "SignatureSpi$ecCVCDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_1);
            addSignatureAlgorithm("SHA224", "CVC-ECDSA", PREFIX + "SignatureSpi$ecCVCDSA224", EACObjectIdentifiers.id_TA_ECDSA_SHA_224);
            addSignatureAlgorithm("SHA256", "CVC-ECDSA", PREFIX + "SignatureSpi$ecCVCDSA256", EACObjectIdentifiers.id_TA_ECDSA_SHA_256);
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
