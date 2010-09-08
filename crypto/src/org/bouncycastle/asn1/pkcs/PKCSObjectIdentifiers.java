package org.bouncycastle.asn1.pkcs;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface PKCSObjectIdentifiers
{
    //
    // pkcs-1 OBJECT IDENTIFIER ::= {
    //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 }
    //
    static final String                 pkcs_1                    = "1.2.840.113549.1.1";
    static final ASN1ObjectIdentifier    rsaEncryption             = new ASN1ObjectIdentifier(pkcs_1 + ".1");
    static final ASN1ObjectIdentifier    md2WithRSAEncryption      = new ASN1ObjectIdentifier(pkcs_1 + ".2");
    static final ASN1ObjectIdentifier    md4WithRSAEncryption      = new ASN1ObjectIdentifier(pkcs_1 + ".3");
    static final ASN1ObjectIdentifier    md5WithRSAEncryption      = new ASN1ObjectIdentifier(pkcs_1 + ".4");
    static final ASN1ObjectIdentifier    sha1WithRSAEncryption     = new ASN1ObjectIdentifier(pkcs_1 + ".5");
    static final ASN1ObjectIdentifier    srsaOAEPEncryptionSET     = new ASN1ObjectIdentifier(pkcs_1 + ".6");
    static final ASN1ObjectIdentifier    id_RSAES_OAEP             = new ASN1ObjectIdentifier(pkcs_1 + ".7");
    static final ASN1ObjectIdentifier    id_mgf1                   = new ASN1ObjectIdentifier(pkcs_1 + ".8");
    static final ASN1ObjectIdentifier    id_pSpecified             = new ASN1ObjectIdentifier(pkcs_1 + ".9");
    static final ASN1ObjectIdentifier    id_RSASSA_PSS             = new ASN1ObjectIdentifier(pkcs_1 + ".10");
    static final ASN1ObjectIdentifier    sha256WithRSAEncryption   = new ASN1ObjectIdentifier(pkcs_1 + ".11");
    static final ASN1ObjectIdentifier    sha384WithRSAEncryption   = new ASN1ObjectIdentifier(pkcs_1 + ".12");
    static final ASN1ObjectIdentifier    sha512WithRSAEncryption   = new ASN1ObjectIdentifier(pkcs_1 + ".13");
    static final ASN1ObjectIdentifier    sha224WithRSAEncryption   = new ASN1ObjectIdentifier(pkcs_1 + ".14");

    //
    // pkcs-3 OBJECT IDENTIFIER ::= {
    //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 3 }
    //
    static final String                 pkcs_3                  = "1.2.840.113549.1.3";
    static final ASN1ObjectIdentifier    dhKeyAgreement          = new ASN1ObjectIdentifier(pkcs_3 + ".1");

    //
    // pkcs-5 OBJECT IDENTIFIER ::= {
    //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 5 }
    //
    static final String                 pkcs_5                  = "1.2.840.113549.1.5";

    static final ASN1ObjectIdentifier    pbeWithMD2AndDES_CBC    = new ASN1ObjectIdentifier(pkcs_5 + ".1");
    static final ASN1ObjectIdentifier    pbeWithMD2AndRC2_CBC    = new ASN1ObjectIdentifier(pkcs_5 + ".4");
    static final ASN1ObjectIdentifier    pbeWithMD5AndDES_CBC    = new ASN1ObjectIdentifier(pkcs_5 + ".3");
    static final ASN1ObjectIdentifier    pbeWithMD5AndRC2_CBC    = new ASN1ObjectIdentifier(pkcs_5 + ".6");
    static final ASN1ObjectIdentifier    pbeWithSHA1AndDES_CBC   = new ASN1ObjectIdentifier(pkcs_5 + ".10");
    static final ASN1ObjectIdentifier    pbeWithSHA1AndRC2_CBC   = new ASN1ObjectIdentifier(pkcs_5 + ".11");

    static final ASN1ObjectIdentifier    id_PBES2                = new ASN1ObjectIdentifier(pkcs_5 + ".13");

    static final ASN1ObjectIdentifier    id_PBKDF2               = new ASN1ObjectIdentifier(pkcs_5 + ".12");

    //
    // encryptionAlgorithm OBJECT IDENTIFIER ::= {
    //       iso(1) member-body(2) us(840) rsadsi(113549) 3 }
    //
    static final String                 encryptionAlgorithm     = "1.2.840.113549.3";

    static final ASN1ObjectIdentifier    des_EDE3_CBC            = new ASN1ObjectIdentifier(encryptionAlgorithm + ".7");
    static final ASN1ObjectIdentifier    RC2_CBC                 = new ASN1ObjectIdentifier(encryptionAlgorithm + ".2");

    //
    // object identifiers for digests
    //
    static final String                 digestAlgorithm     = "1.2.840.113549.2";
    //
    // md2 OBJECT IDENTIFIER ::=
    //      {iso(1) member-body(2) US(840) rsadsi(113549) digestAlgorithm(2) 2}
    //
    static final ASN1ObjectIdentifier    md2                     = new ASN1ObjectIdentifier(digestAlgorithm + ".2");

    //
    // md4 OBJECT IDENTIFIER ::=
    //      {iso(1) member-body(2) US(840) rsadsi(113549) digestAlgorithm(2) 4}
    //
    static final ASN1ObjectIdentifier    md4 = new ASN1ObjectIdentifier(digestAlgorithm + ".4");

    //
    // md5 OBJECT IDENTIFIER ::=
    //      {iso(1) member-body(2) US(840) rsadsi(113549) digestAlgorithm(2) 5}
    //
    static final ASN1ObjectIdentifier    md5                     = new ASN1ObjectIdentifier(digestAlgorithm + ".5");

    static final ASN1ObjectIdentifier    id_hmacWithSHA1         = new ASN1ObjectIdentifier(digestAlgorithm + ".7");
    static final ASN1ObjectIdentifier    id_hmacWithSHA224       = new ASN1ObjectIdentifier(digestAlgorithm + ".8");
    static final ASN1ObjectIdentifier    id_hmacWithSHA256       = new ASN1ObjectIdentifier(digestAlgorithm + ".9");
    static final ASN1ObjectIdentifier    id_hmacWithSHA384       = new ASN1ObjectIdentifier(digestAlgorithm + ".10");
    static final ASN1ObjectIdentifier    id_hmacWithSHA512       = new ASN1ObjectIdentifier(digestAlgorithm + ".11");

    //
    // pkcs-7 OBJECT IDENTIFIER ::= {
    //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 7 }
    //
    static final String                 pkcs_7                  = "1.2.840.113549.1.7";
    static final ASN1ObjectIdentifier    data                    = new ASN1ObjectIdentifier(pkcs_7 + ".1");
    static final ASN1ObjectIdentifier    signedData              = new ASN1ObjectIdentifier(pkcs_7 + ".2");
    static final ASN1ObjectIdentifier    envelopedData           = new ASN1ObjectIdentifier(pkcs_7 + ".3");
    static final ASN1ObjectIdentifier    signedAndEnvelopedData  = new ASN1ObjectIdentifier(pkcs_7 + ".4");
    static final ASN1ObjectIdentifier    digestedData            = new ASN1ObjectIdentifier(pkcs_7 + ".5");
    static final ASN1ObjectIdentifier    encryptedData           = new ASN1ObjectIdentifier(pkcs_7 + ".6");

    //
    // pkcs-9 OBJECT IDENTIFIER ::= {
    //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 9 }
    //
    static final String                 pkcs_9                  = "1.2.840.113549.1.9";

    static final ASN1ObjectIdentifier    pkcs_9_at_emailAddress  = new ASN1ObjectIdentifier(pkcs_9 + ".1");
    static final ASN1ObjectIdentifier    pkcs_9_at_unstructuredName = new ASN1ObjectIdentifier(pkcs_9 + ".2");
    static final ASN1ObjectIdentifier    pkcs_9_at_contentType = new ASN1ObjectIdentifier(pkcs_9 + ".3");
    static final ASN1ObjectIdentifier    pkcs_9_at_messageDigest = new ASN1ObjectIdentifier(pkcs_9 + ".4");
    static final ASN1ObjectIdentifier    pkcs_9_at_signingTime = new ASN1ObjectIdentifier(pkcs_9 + ".5");
    static final ASN1ObjectIdentifier    pkcs_9_at_counterSignature = new ASN1ObjectIdentifier(pkcs_9 + ".6");
    static final ASN1ObjectIdentifier    pkcs_9_at_challengePassword = new ASN1ObjectIdentifier(pkcs_9 + ".7");
    static final ASN1ObjectIdentifier    pkcs_9_at_unstructuredAddress = new ASN1ObjectIdentifier(pkcs_9 + ".8");
    static final ASN1ObjectIdentifier    pkcs_9_at_extendedCertificateAttributes = new ASN1ObjectIdentifier(pkcs_9 + ".9");

    static final ASN1ObjectIdentifier    pkcs_9_at_signingDescription = new ASN1ObjectIdentifier(pkcs_9 + ".13");
    static final ASN1ObjectIdentifier    pkcs_9_at_extensionRequest = new ASN1ObjectIdentifier(pkcs_9 + ".14");
    static final ASN1ObjectIdentifier    pkcs_9_at_smimeCapabilities = new ASN1ObjectIdentifier(pkcs_9 + ".15");

    static final ASN1ObjectIdentifier    pkcs_9_at_friendlyName  = new ASN1ObjectIdentifier(pkcs_9 + ".20");
    static final ASN1ObjectIdentifier    pkcs_9_at_localKeyId    = new ASN1ObjectIdentifier(pkcs_9 + ".21");

    /** @deprecated use x509Certificate instead */
    static final ASN1ObjectIdentifier    x509certType            = new ASN1ObjectIdentifier(pkcs_9 + ".22.1");

    static final String                 certTypes               = pkcs_9 + ".22";
    static final ASN1ObjectIdentifier    x509Certificate         = new ASN1ObjectIdentifier(certTypes + ".1");
    static final ASN1ObjectIdentifier    sdsiCertificate         = new ASN1ObjectIdentifier(certTypes + ".2");

    static final String                 crlTypes                = pkcs_9 + ".23";
    static final ASN1ObjectIdentifier    x509Crl                 = new ASN1ObjectIdentifier(crlTypes + ".1");

    static final ASN1ObjectIdentifier    id_alg_PWRI_KEK    = new ASN1ObjectIdentifier(pkcs_9 + ".16.3.9");

    //
    // SMIME capability sub oids.
    //
    static final ASN1ObjectIdentifier    preferSignedData        = new ASN1ObjectIdentifier(pkcs_9 + ".15.1");
    static final ASN1ObjectIdentifier    canNotDecryptAny        = new ASN1ObjectIdentifier(pkcs_9 + ".15.2");
    static final ASN1ObjectIdentifier    sMIMECapabilitiesVersions = new ASN1ObjectIdentifier(pkcs_9 + ".15.3");

    //
    // id-ct OBJECT IDENTIFIER ::= {iso(1) member-body(2) usa(840)
    // rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) ct(1)}
    //
    static String id_ct = "1.2.840.113549.1.9.16.1";

    static final ASN1ObjectIdentifier    id_ct_authData          = new ASN1ObjectIdentifier(id_ct + ".2");
    static final ASN1ObjectIdentifier    id_ct_TSTInfo           = new ASN1ObjectIdentifier(id_ct + ".4");
    static final ASN1ObjectIdentifier    id_ct_compressedData    = new ASN1ObjectIdentifier(id_ct + ".9");
    static final ASN1ObjectIdentifier    id_ct_authEnvelopedData = new ASN1ObjectIdentifier(id_ct + ".23");

    //
    // id-cti OBJECT IDENTIFIER ::= {iso(1) member-body(2) usa(840)
    // rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) cti(6)}
    //
    static String id_cti = "1.2.840.113549.1.9.16.6";
    
    static final ASN1ObjectIdentifier    id_cti_ets_proofOfOrigin  = new ASN1ObjectIdentifier(id_cti + ".1");
    static final ASN1ObjectIdentifier    id_cti_ets_proofOfReceipt = new ASN1ObjectIdentifier(id_cti + ".2");
    static final ASN1ObjectIdentifier    id_cti_ets_proofOfDelivery = new ASN1ObjectIdentifier(id_cti + ".3");
    static final ASN1ObjectIdentifier    id_cti_ets_proofOfSender = new ASN1ObjectIdentifier(id_cti + ".4");
    static final ASN1ObjectIdentifier    id_cti_ets_proofOfApproval = new ASN1ObjectIdentifier(id_cti + ".5");
    static final ASN1ObjectIdentifier    id_cti_ets_proofOfCreation = new ASN1ObjectIdentifier(id_cti + ".6");
    
    //
    // id-aa OBJECT IDENTIFIER ::= {iso(1) member-body(2) usa(840)
    // rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) attributes(2)}
    //
    static String id_aa = "1.2.840.113549.1.9.16.2";


    static final ASN1ObjectIdentifier id_aa_receiptRequest = new ASN1ObjectIdentifier(id_aa + ".1");
    
    static final ASN1ObjectIdentifier id_aa_contentHint = new ASN1ObjectIdentifier(id_aa + ".4"); // See RFC 2634
    static final ASN1ObjectIdentifier id_aa_msgSigDigest = new ASN1ObjectIdentifier(id_aa + ".5");
    static final ASN1ObjectIdentifier id_aa_contentReference = new ASN1ObjectIdentifier(id_aa + ".10");
    /*
     * id-aa-encrypKeyPref OBJECT IDENTIFIER ::= {id-aa 11}
     * 
     */
    static final ASN1ObjectIdentifier id_aa_encrypKeyPref = new ASN1ObjectIdentifier(id_aa + ".11");
    static final ASN1ObjectIdentifier id_aa_signingCertificate = new ASN1ObjectIdentifier(id_aa + ".12");
    static final ASN1ObjectIdentifier id_aa_signingCertificateV2 = new ASN1ObjectIdentifier(id_aa + ".47");

    static final ASN1ObjectIdentifier id_aa_contentIdentifier = new ASN1ObjectIdentifier(id_aa + ".7"); // See RFC 2634

    /*
     * RFC 3126
     */
    static final ASN1ObjectIdentifier id_aa_signatureTimeStampToken = new ASN1ObjectIdentifier(id_aa + ".14");
    
    static final ASN1ObjectIdentifier id_aa_ets_sigPolicyId = new ASN1ObjectIdentifier(id_aa + ".15");
    static final ASN1ObjectIdentifier id_aa_ets_commitmentType = new ASN1ObjectIdentifier(id_aa + ".16");
    static final ASN1ObjectIdentifier id_aa_ets_signerLocation = new ASN1ObjectIdentifier(id_aa + ".17");
    static final ASN1ObjectIdentifier id_aa_ets_signerAttr = new ASN1ObjectIdentifier(id_aa + ".18");
    static final ASN1ObjectIdentifier id_aa_ets_otherSigCert = new ASN1ObjectIdentifier(id_aa + ".19");
    static final ASN1ObjectIdentifier id_aa_ets_contentTimestamp = new ASN1ObjectIdentifier(id_aa + ".20");
    static final ASN1ObjectIdentifier id_aa_ets_certificateRefs = new ASN1ObjectIdentifier(id_aa + ".21");
    static final ASN1ObjectIdentifier id_aa_ets_revocationRefs = new ASN1ObjectIdentifier(id_aa + ".22");
    static final ASN1ObjectIdentifier id_aa_ets_certValues = new ASN1ObjectIdentifier(id_aa + ".23");
    static final ASN1ObjectIdentifier id_aa_ets_revocationValues = new ASN1ObjectIdentifier(id_aa + ".24");
    static final ASN1ObjectIdentifier id_aa_ets_escTimeStamp = new ASN1ObjectIdentifier(id_aa + ".25");
    static final ASN1ObjectIdentifier id_aa_ets_certCRLTimestamp = new ASN1ObjectIdentifier(id_aa + ".26");
    static final ASN1ObjectIdentifier id_aa_ets_archiveTimestamp = new ASN1ObjectIdentifier(id_aa + ".27");

    /** @deprecated use id_aa_ets_sigPolicyId instead */
    static final ASN1ObjectIdentifier id_aa_sigPolicyId = id_aa_ets_sigPolicyId;
    /** @deprecated use id_aa_ets_commitmentType instead */
    static final ASN1ObjectIdentifier id_aa_commitmentType = id_aa_ets_commitmentType;
    /** @deprecated use id_aa_ets_signerLocation instead */
    static final ASN1ObjectIdentifier id_aa_signerLocation = id_aa_ets_signerLocation;
    /** @deprecated use id_aa_ets_otherSigCert instead */
    static final ASN1ObjectIdentifier id_aa_otherSigCert = id_aa_ets_otherSigCert;
    
    //
    // id-spq OBJECT IDENTIFIER ::= {iso(1) member-body(2) usa(840)
    // rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-spq(5)}
    //
    final String id_spq = "1.2.840.113549.1.9.16.5";

    static final ASN1ObjectIdentifier id_spq_ets_uri = new ASN1ObjectIdentifier(id_spq + ".1");
    static final ASN1ObjectIdentifier id_spq_ets_unotice = new ASN1ObjectIdentifier(id_spq + ".2");

    //
    // pkcs-12 OBJECT IDENTIFIER ::= {
    //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 12 }
    //
    static final String                 pkcs_12                  = "1.2.840.113549.1.12";
    static final String                 bagtypes                 = pkcs_12 + ".10.1";

    static final ASN1ObjectIdentifier    keyBag                  = new ASN1ObjectIdentifier(bagtypes + ".1");
    static final ASN1ObjectIdentifier    pkcs8ShroudedKeyBag     = new ASN1ObjectIdentifier(bagtypes + ".2");
    static final ASN1ObjectIdentifier    certBag                 = new ASN1ObjectIdentifier(bagtypes + ".3");
    static final ASN1ObjectIdentifier    crlBag                  = new ASN1ObjectIdentifier(bagtypes + ".4");
    static final ASN1ObjectIdentifier    secretBag               = new ASN1ObjectIdentifier(bagtypes + ".5");
    static final ASN1ObjectIdentifier    safeContentsBag         = new ASN1ObjectIdentifier(bagtypes + ".6");

    static final String pkcs_12PbeIds  = pkcs_12 + ".1";

    static final ASN1ObjectIdentifier    pbeWithSHAAnd128BitRC4 = new ASN1ObjectIdentifier(pkcs_12PbeIds + ".1");
    static final ASN1ObjectIdentifier    pbeWithSHAAnd40BitRC4  = new ASN1ObjectIdentifier(pkcs_12PbeIds + ".2");
    static final ASN1ObjectIdentifier    pbeWithSHAAnd3_KeyTripleDES_CBC = new ASN1ObjectIdentifier(pkcs_12PbeIds + ".3");
    static final ASN1ObjectIdentifier    pbeWithSHAAnd2_KeyTripleDES_CBC = new ASN1ObjectIdentifier(pkcs_12PbeIds + ".4");
    static final ASN1ObjectIdentifier    pbeWithSHAAnd128BitRC2_CBC = new ASN1ObjectIdentifier(pkcs_12PbeIds + ".5");
    static final ASN1ObjectIdentifier    pbewithSHAAnd40BitRC2_CBC = new ASN1ObjectIdentifier(pkcs_12PbeIds + ".6");

    static final ASN1ObjectIdentifier    id_alg_CMS3DESwrap = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.3.6");
    static final ASN1ObjectIdentifier    id_alg_CMSRC2wrap = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.3.7");
}

