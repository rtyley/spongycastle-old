package org.bouncycastle.asn1.sec;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

public interface SECObjectIdentifiers
{
    /**
     *  ellipticCurve OBJECT IDENTIFIER ::= {
     *        iso(1) identified-organization(3) certicom(132) curve(0)
     *  }
     */
    static final DERObjectIdentifier ellipticCurve = new DERObjectIdentifier("1.3.132.0");

    static final DERObjectIdentifier secp192r1 = X9ObjectIdentifiers.prime192v1; 
    static final DERObjectIdentifier sect163k1 = new DERObjectIdentifier(ellipticCurve + ".1");
    static final DERObjectIdentifier sect163r1 = new DERObjectIdentifier(ellipticCurve + ".2");
    static final DERObjectIdentifier sect163r2 = new DERObjectIdentifier(ellipticCurve + ".15"); 
    static final DERObjectIdentifier secp224r1 = new DERObjectIdentifier(ellipticCurve + ".33"); 
    static final DERObjectIdentifier sect233k1 = new DERObjectIdentifier(ellipticCurve + ".26"); 
    static final DERObjectIdentifier sect233r1 = new DERObjectIdentifier(ellipticCurve + ".27"); 
    static final DERObjectIdentifier secp256r1 = X9ObjectIdentifiers.prime256v1;
    static final DERObjectIdentifier sect283k1 = new DERObjectIdentifier(ellipticCurve + ".16"); 
    static final DERObjectIdentifier sect283r1 = new DERObjectIdentifier(ellipticCurve + ".17"); 
    static final DERObjectIdentifier secp384r1 = new DERObjectIdentifier(ellipticCurve + ".34"); 
    static final DERObjectIdentifier sect409k1 = new DERObjectIdentifier(ellipticCurve + ".36"); 
    static final DERObjectIdentifier sect409r1 = new DERObjectIdentifier(ellipticCurve + ".37");   
    static final DERObjectIdentifier secp521r1 = new DERObjectIdentifier(ellipticCurve + ".35"); 
    static final DERObjectIdentifier sect571k1 = new DERObjectIdentifier(ellipticCurve + ".38"); 
    static final DERObjectIdentifier sect571r1 = new DERObjectIdentifier(ellipticCurve + ".39"); 
}
