package org.bouncycastle.asn1.eac;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface EACObjectIdentifiers
{
    // bsi-de OBJECT IDENTIFIER ::= {
    //         itu-t(0) identified-organization(4) etsi(0)
    //         reserved(127) etsi-identified-organization(0) 7
    //     }
    static final ASN1ObjectIdentifier    bsi_de      = new ASN1ObjectIdentifier("0.4.0.127.0.7");

    // id-PK OBJECT IDENTIFIER ::= {
    //         bsi-de protocols(2) smartcard(2) 1
    //     }
    static final ASN1ObjectIdentifier    id_PK = new ASN1ObjectIdentifier(bsi_de + ".2.2.1");

    static final ASN1ObjectIdentifier    id_PK_DH = new ASN1ObjectIdentifier(id_PK + ".1");
    static final ASN1ObjectIdentifier    id_PK_ECDH = new ASN1ObjectIdentifier(id_PK + ".2");

    // id-CA OBJECT IDENTIFIER ::= {
    //         bsi-de protocols(2) smartcard(2) 3
    //     }
    static final ASN1ObjectIdentifier    id_CA = new ASN1ObjectIdentifier(bsi_de + ".2.2.3");
    static final ASN1ObjectIdentifier    id_CA_DH = new ASN1ObjectIdentifier(id_CA + ".1");
    static final ASN1ObjectIdentifier    id_CA_DH_3DES_CBC_CBC = new ASN1ObjectIdentifier(id_CA_DH + ".1");
    static final ASN1ObjectIdentifier    id_CA_ECDH = new ASN1ObjectIdentifier(id_CA + ".2");
    static final ASN1ObjectIdentifier    id_CA_ECDH_3DES_CBC_CBC = new ASN1ObjectIdentifier(id_CA_ECDH + ".1");

    //
    // id-TA OBJECT IDENTIFIER ::= {
    //     bsi-de protocols(2) smartcard(2) 2
    // }
    static final ASN1ObjectIdentifier    id_TA = new ASN1ObjectIdentifier(bsi_de + ".2.2.2");

    static final ASN1ObjectIdentifier    id_TA_RSA = new ASN1ObjectIdentifier(id_TA + ".1");
    static final ASN1ObjectIdentifier    id_TA_RSA_v1_5_SHA_1 = new ASN1ObjectIdentifier(id_TA_RSA + ".1");
    static final ASN1ObjectIdentifier    id_TA_RSA_v1_5_SHA_256 = new ASN1ObjectIdentifier(id_TA_RSA + ".2");
    static final ASN1ObjectIdentifier    id_TA_RSA_PSS_SHA_1 = new ASN1ObjectIdentifier(id_TA_RSA + ".3");
    static final ASN1ObjectIdentifier    id_TA_RSA_PSS_SHA_256 = new ASN1ObjectIdentifier(id_TA_RSA + ".4");
    static final ASN1ObjectIdentifier    id_TA_ECDSA = new ASN1ObjectIdentifier(id_TA + ".2");
    static final ASN1ObjectIdentifier    id_TA_ECDSA_SHA_1 = new ASN1ObjectIdentifier(id_TA_ECDSA + ".1");
    static final ASN1ObjectIdentifier    id_TA_ECDSA_SHA_224 = new ASN1ObjectIdentifier(id_TA_ECDSA + ".2");
    static final ASN1ObjectIdentifier    id_TA_ECDSA_SHA_256 = new ASN1ObjectIdentifier(id_TA_ECDSA + ".3");

    static final ASN1ObjectIdentifier    id_TA_ECDSA_SHA_384 = new ASN1ObjectIdentifier(id_TA_ECDSA + ".4");
    static final ASN1ObjectIdentifier    id_TA_ECDSA_SHA_512 = new ASN1ObjectIdentifier(id_TA_ECDSA + ".5");

    /**
     * id-EAC-ePassport OBJECT IDENTIFIER ::= {
     * bsi-de applications(3) mrtd(1) roles(2) 1}
     */
    static final ASN1ObjectIdentifier id_EAC_ePassport = new ASN1ObjectIdentifier(bsi_de + ".3.1.2.1");

}
