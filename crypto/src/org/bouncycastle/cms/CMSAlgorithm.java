package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

public class CMSAlgorithm
{
    public static final ASN1ObjectIdentifier  DES_EDE3_CBC    = new ASN1ObjectIdentifier(PKCSObjectIdentifiers.des_EDE3_CBC.getId());
    public static final ASN1ObjectIdentifier  RC2_CBC         = new ASN1ObjectIdentifier(PKCSObjectIdentifiers.RC2_CBC.getId());
    public static final ASN1ObjectIdentifier  IDEA_CBC        = new ASN1ObjectIdentifier("1.3.6.1.4.1.188.7.1.1.2");
    public static final ASN1ObjectIdentifier  CAST5_CBC       = new ASN1ObjectIdentifier("1.2.840.113533.7.66.10");
    public static final ASN1ObjectIdentifier  AES128_CBC      = new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_aes128_CBC.getId());
    public static final ASN1ObjectIdentifier  AES192_CBC      = new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_aes192_CBC.getId());
    public static final ASN1ObjectIdentifier  AES256_CBC      = new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_aes256_CBC.getId());
    public static final ASN1ObjectIdentifier  CAMELLIA128_CBC = new ASN1ObjectIdentifier(NTTObjectIdentifiers.id_camellia128_cbc.getId());
    public static final ASN1ObjectIdentifier  CAMELLIA192_CBC = new ASN1ObjectIdentifier(NTTObjectIdentifiers.id_camellia192_cbc.getId());
    public static final ASN1ObjectIdentifier  CAMELLIA256_CBC = new ASN1ObjectIdentifier(NTTObjectIdentifiers.id_camellia256_cbc.getId());
    public static final ASN1ObjectIdentifier  SEED_CBC        = new ASN1ObjectIdentifier(KISAObjectIdentifiers.id_seedCBC.getId());

    public static final ASN1ObjectIdentifier  DES_EDE3_WRAP   = new ASN1ObjectIdentifier(PKCSObjectIdentifiers.id_alg_CMS3DESwrap.getId());
    public static final ASN1ObjectIdentifier  AES128_WRAP     = new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_aes128_wrap.getId());
    public static final ASN1ObjectIdentifier  AES192_WRAP     = new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_aes192_wrap.getId());
    public static final ASN1ObjectIdentifier  AES256_WRAP     = new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_aes256_wrap.getId());
    public static final ASN1ObjectIdentifier  CAMELLIA128_WRAP = new ASN1ObjectIdentifier(NTTObjectIdentifiers.id_camellia128_wrap.getId());
    public static final ASN1ObjectIdentifier  CAMELLIA192_WRAP = new ASN1ObjectIdentifier(NTTObjectIdentifiers.id_camellia192_wrap.getId());
    public static final ASN1ObjectIdentifier  CAMELLIA256_WRAP = new ASN1ObjectIdentifier(NTTObjectIdentifiers.id_camellia256_wrap.getId());
    public static final ASN1ObjectIdentifier  SEED_WRAP       = new ASN1ObjectIdentifier(KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap.getId());

    public static final ASN1ObjectIdentifier  ECDH_SHA1KDF    = new ASN1ObjectIdentifier(X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme.getId());
    public static final ASN1ObjectIdentifier  ECMQV_SHA1KDF   = new ASN1ObjectIdentifier(X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme.getId());

}
