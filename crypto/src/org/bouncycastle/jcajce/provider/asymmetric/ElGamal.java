package org.bouncycastle.jcajce.provider.asymmetric;

import java.util.HashMap;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyFactorySpi;

public class ElGamal
{
    public static class Mappings
        extends HashMap
    {
        public Mappings()
        {
            put("AlgorithmParameters.ELGAMAL", "org.bouncycastle.jce.provider.JDKAlgorithmParameters$ElGamal");
            put("Cipher.ELGAMAL", "org.bouncycastle.jce.provider.JCEElGamalCipher$NoPadding");
            put("Cipher.ELGAMAL/PKCS1", "org.bouncycastle.jce.provider.JCEElGamalCipher$PKCS1v1_5Padding");
            put("KeyFactory.ELGAMAL", "org.bouncycastle.jce.provider.JDKKeyFactory$ElGamal");
            put("KeyFactory.ElGamal", "org.bouncycastle.jce.provider.JDKKeyFactory$ElGamal");
        }

        private void addKeyFactory(ASN1ObjectIdentifier oid)
        {
            put("Alg.Alias.KeyFactory." + oid, "ELGAMAL");
            X509.registerKeyFactory(oid, new KeyFactorySpi());
        }

        private void addKeyPairGenerator(ASN1ObjectIdentifier oid)
        {
            put("Alg.Alias.KeyPairGenerator." + oid, "ELGAMAL");
        }
    }
}
