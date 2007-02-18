package org.bouncycastle.jce.provider.symmetric;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;

import java.util.HashMap;

public class AESMappings
    extends HashMap
{
    /**
     * These three got introduced in some messages as a result of a typo in an
     * early document. We don't produce anything using these OID values, but we'll
     * read them.
     */
    private static final String wrongAES128 = "2.16.840.1.101.3.4.2";
    private static final String wrongAES192 = "2.16.840.1.101.3.4.22";
    private static final String wrongAES256 = "2.16.840.1.101.3.4.42";

    public AESMappings()
    {
        put("AlgorithmParameters.AES", "org.bouncycastle.jce.provider.symmetric.AES$AlgParams");
        put("Alg.Alias.AlgorithmParameters." + wrongAES128, "AES");
        put("Alg.Alias.AlgorithmParameters." + wrongAES192, "AES");
        put("Alg.Alias.AlgorithmParameters." + wrongAES256, "AES");
        put("Alg.Alias.AlgorithmParameters." + NISTObjectIdentifiers.id_aes128_CBC, "AES");
        put("Alg.Alias.AlgorithmParameters." + NISTObjectIdentifiers.id_aes192_CBC, "AES");
        put("Alg.Alias.AlgorithmParameters." + NISTObjectIdentifiers.id_aes256_CBC, "AES");

        put("AlgorithmParameterGenerator.AES", "org.bouncycastle.jce.provider.symmetric.AES$AlgParamGen");
        put("Alg.Alias.AlgorithmParameterGenerator." + wrongAES128, "AES");
        put("Alg.Alias.AlgorithmParameterGenerator." + wrongAES192, "AES");
        put("Alg.Alias.AlgorithmParameterGenerator." + wrongAES256, "AES");
        put("Alg.Alias.AlgorithmParameterGenerator." + NISTObjectIdentifiers.id_aes128_CBC, "AES");
        put("Alg.Alias.AlgorithmParameterGenerator." + NISTObjectIdentifiers.id_aes192_CBC, "AES");
        put("Alg.Alias.AlgorithmParameterGenerator." + NISTObjectIdentifiers.id_aes256_CBC, "AES");

        put("Cipher.AES", "org.bouncycastle.jce.provider.symmetric.AES$ECB");
        put("Alg.Alias.Cipher." + wrongAES128, "AES");
        put("Alg.Alias.Cipher." + wrongAES192, "AES");
        put("Alg.Alias.Cipher." + wrongAES256, "AES");
        put("Cipher." + NISTObjectIdentifiers.id_aes128_ECB, "org.bouncycastle.jce.provider.symmetric.AES$ECB");
        put("Cipher." + NISTObjectIdentifiers.id_aes192_ECB, "org.bouncycastle.jce.provider.symmetric.AES$ECB");
        put("Cipher." + NISTObjectIdentifiers.id_aes256_ECB, "org.bouncycastle.jce.provider.symmetric.AES$ECB");
        put("Cipher." + NISTObjectIdentifiers.id_aes128_CBC, "org.bouncycastle.jce.provider.symmetric.AES$CBC");
        put("Cipher." + NISTObjectIdentifiers.id_aes192_CBC, "org.bouncycastle.jce.provider.symmetric.AES$CBC");
        put("Cipher." + NISTObjectIdentifiers.id_aes256_CBC, "org.bouncycastle.jce.provider.symmetric.AES$CBC");
        put("Cipher." + NISTObjectIdentifiers.id_aes128_OFB, "org.bouncycastle.jce.provider.symmetric.AES$OFB");
        put("Cipher." + NISTObjectIdentifiers.id_aes192_OFB, "org.bouncycastle.jce.provider.symmetric.AES$OFB");
        put("Cipher." + NISTObjectIdentifiers.id_aes256_OFB, "org.bouncycastle.jce.provider.symmetric.AES$OFB");
        put("Cipher." + NISTObjectIdentifiers.id_aes128_CFB, "org.bouncycastle.jce.provider.symmetric.AES$CFB");
        put("Cipher." + NISTObjectIdentifiers.id_aes192_CFB, "org.bouncycastle.jce.provider.symmetric.AES$CFB");
        put("Cipher." + NISTObjectIdentifiers.id_aes256_CFB, "org.bouncycastle.jce.provider.symmetric.AES$CFB");
        put("Cipher.AESWRAP", "org.bouncycastle.jce.provider.symmetric.AES$Wrap");
        put("Alg.Alias.Cipher." + NISTObjectIdentifiers.id_aes128_wrap, "AESWRAP");
        put("Alg.Alias.Cipher." + NISTObjectIdentifiers.id_aes192_wrap, "AESWRAP");
        put("Alg.Alias.Cipher." + NISTObjectIdentifiers.id_aes256_wrap, "AESWRAP");
        put("Cipher.AESRFC3211WRAP", "org.bouncycastle.jce.provider.symmetric.AES$RFC3211Wrap");

        put("KeyGenerator.AES", "org.bouncycastle.jce.provider.symmetric.AES$KeyGen");
        put("KeyGenerator.2.16.840.1.101.3.4.2", "org.bouncycastle.jce.provider.symmetric.AES$KeyGen128");
        put("KeyGenerator.2.16.840.1.101.3.4.22", "org.bouncycastle.jce.provider.symmetric.AES$KeyGen192");
        put("KeyGenerator.2.16.840.1.101.3.4.42", "org.bouncycastle.jce.provider.symmetric.AES$KeyGen256");
        put("KeyGenerator." + NISTObjectIdentifiers.id_aes128_ECB, "org.bouncycastle.jce.provider.symmetric.AES$KeyGen128");
        put("KeyGenerator." + NISTObjectIdentifiers.id_aes128_CBC, "org.bouncycastle.jce.provider.symmetric.AES$KeyGen128");
        put("KeyGenerator." + NISTObjectIdentifiers.id_aes128_OFB, "org.bouncycastle.jce.provider.symmetric.AES$KeyGen128");
        put("KeyGenerator." + NISTObjectIdentifiers.id_aes128_CFB, "org.bouncycastle.jce.provider.symmetric.AES$KeyGen128");
        put("KeyGenerator." + NISTObjectIdentifiers.id_aes192_ECB, "org.bouncycastle.jce.provider.symmetric.AES$KeyGen192");
        put("KeyGenerator." + NISTObjectIdentifiers.id_aes192_CBC, "org.bouncycastle.jce.provider.symmetric.AES$KeyGen192");
        put("KeyGenerator." + NISTObjectIdentifiers.id_aes192_OFB, "org.bouncycastle.jce.provider.symmetric.AES$KeyGen192");
        put("KeyGenerator." + NISTObjectIdentifiers.id_aes192_CFB, "org.bouncycastle.jce.provider.symmetric.AES$KeyGen192");
        put("KeyGenerator." + NISTObjectIdentifiers.id_aes256_ECB, "org.bouncycastle.jce.provider.symmetric.AES$KeyGen256");
        put("KeyGenerator." + NISTObjectIdentifiers.id_aes256_CBC, "org.bouncycastle.jce.provider.symmetric.AES$KeyGen256");
        put("KeyGenerator." + NISTObjectIdentifiers.id_aes256_OFB, "org.bouncycastle.jce.provider.symmetric.AES$KeyGen256");
        put("KeyGenerator." + NISTObjectIdentifiers.id_aes256_CFB, "org.bouncycastle.jce.provider.symmetric.AES$KeyGen256");
        put("KeyGenerator.AESWRAP", "org.bouncycastle.jce.provider.symmetric.AES$KeyGen");
        put("KeyGenerator." + NISTObjectIdentifiers.id_aes128_wrap, "org.bouncycastle.jce.provider.symmetric.AES$KeyGen128");
        put("KeyGenerator." + NISTObjectIdentifiers.id_aes192_wrap, "org.bouncycastle.jce.provider.symmetric.AES$KeyGen192");
        put("KeyGenerator." + NISTObjectIdentifiers.id_aes256_wrap, "org.bouncycastle.jce.provider.symmetric.AES$KeyGen256");
    }
}
