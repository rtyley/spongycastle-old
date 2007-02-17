package org.bouncycastle.jce.provider.symmetric;

import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;

import java.util.HashMap;

public class CamelliaMappings
    extends HashMap
{
    public CamelliaMappings()
    {
        put("Cipher.CAMELLIA", "org.bouncycastle.jce.provider.symmetric.Camellia$ECB");
        put("Cipher." + NTTObjectIdentifiers.id_camellia128_cbc, "org.bouncycastle.jce.provider.symmetric.Camellia$CBC");
        put("Cipher." + NTTObjectIdentifiers.id_camellia192_cbc, "org.bouncycastle.jce.provider.symmetric.Camellia$CBC");
        put("Cipher." + NTTObjectIdentifiers.id_camellia256_cbc, "org.bouncycastle.jce.provider.symmetric.Camellia$CBC");

        put("Cipher.CAMELLIARFC3211WRAP", "org.bouncycastle.jce.provider.symmetric.Camellia$RFC3211Wrap");
        put("Cipher.CAMELLIAWRAP", "org.bouncycastle.jce.provider.symmetric.Camellia$Wrap");
        put("Alg.Alias.Cipher." + NTTObjectIdentifiers.id_camellia128_wrap, "CAMELLIAWRAP");
        put("Alg.Alias.Cipher." + NTTObjectIdentifiers.id_camellia192_wrap, "CAMELLIAWRAP");
        put("Alg.Alias.Cipher." + NTTObjectIdentifiers.id_camellia256_wrap, "CAMELLIAWRAP");

        put("KeyGenerator.CAMELLIA", "org.bouncycastle.jce.provider.symmetric.Camellia$KeyGen");
        put("KeyGenerator." + NTTObjectIdentifiers.id_camellia128_wrap, "org.bouncycastle.jce.provider.symmetric.Camellia$KeyGen128");
        put("KeyGenerator." + NTTObjectIdentifiers.id_camellia192_wrap, "org.bouncycastle.jce.provider.symmetric.Camellia$KeyGen192");
        put("KeyGenerator." + NTTObjectIdentifiers.id_camellia256_wrap, "org.bouncycastle.jce.provider.symmetric.Camellia$KeyGen256");
        put("KeyGenerator." + NTTObjectIdentifiers.id_camellia128_cbc, "org.bouncycastle.jce.provider.symmetric.Camellia$KeyGen128");
        put("KeyGenerator." + NTTObjectIdentifiers.id_camellia192_cbc, "org.bouncycastle.jce.provider.symmetric.Camellia$KeyGen192");
        put("KeyGenerator." + NTTObjectIdentifiers.id_camellia256_cbc, "org.bouncycastle.jce.provider.symmetric.Camellia$KeyGen256");
    }
}
