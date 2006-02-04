package org.bouncycastle.asn1.sec;

import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Hashtable;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

public class SECNamedCurves
{
    /*
     * secp224r1 (NIST P-224)
     */
    // p = 2^224 - 2^96 + 1
    static final BigInteger secp224r1P = new BigInteger(
            "26959946667150639794667015087019630673557916260026308143510066298881");

    // a = -3, b = b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4
    static final ECCurve secp224r1Curve = new ECCurve.Fp(secp224r1P,
            new BigInteger("26959946667150639794667015087019630673557916260026308143510066298878"),
            new BigInteger("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4", 16));

    // x = b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21
    static final ECFieldElement secp224r1x = new ECFieldElement.Fp(
        secp224r1P,
        new BigInteger("b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21", 16));

    // y = bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34
    static final ECFieldElement secp224r1y = new ECFieldElement.Fp(
        secp224r1P,
        new BigInteger("bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34", 16));

    static final ECPoint secp224r1BasePoint = new ECPoint.Fp(
        secp224r1Curve, secp224r1x, secp224r1y, false);

    static final BigInteger secp224r1n = new BigInteger("26959946667150639794667015087019625940457807714424391721682722368061");

    static final BigInteger secp224r1h = new BigInteger("1");

//    static final byte[] secp224r1Seed = (Hex.decode("bd71344799d5c7fcdc45b59fa3b9ab8f6a948bc5"));
    static final byte[] secp224r1Seed = null;
    
    static final X9ECParameters secp224r1 = new X9ECParameters(
            secp224r1Curve,
            secp224r1BasePoint,
            secp224r1n,
            secp224r1h,
            secp224r1Seed);

    /*
     * secp256r1 (NIST P-256)
     */
    // p = 2^256 - 2^224 + 2^192 + 2^96 - 1
    static final BigInteger secp256r1P = new BigInteger(
            "115792089210356248762697446949407573530086143415290314195533631308867097853951");

    // a = -3, b = 5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    static final ECCurve secp256r1Curve = new ECCurve.Fp(secp256r1P,
            new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948"),
            new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16));

    // x = 6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
    static final ECFieldElement secp256r1x = new ECFieldElement.Fp(
        secp256r1P,
        new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16));

    // y = 4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
    static final ECFieldElement secp256r1y = new ECFieldElement.Fp(
        secp256r1P,
        new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16));

    static final ECPoint secp256r1BasePoint = new ECPoint.Fp(
//        secp256r1Curve, secp256r1x, secp256r1y);
        secp256r1Curve, secp256r1x, secp256r1y, false);

    static final BigInteger secp256r1n = new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369");

    static final BigInteger secp256r1h = new BigInteger("1");

//    static final byte[] secp256r1Seed = (Hex.decode("c49d360886e704936a6678e1139d26b7819f7e90"));
    static final byte[] secp256r1Seed = null;
    
    static final X9ECParameters secp256r1 = new X9ECParameters(
            secp256r1Curve,
            secp256r1BasePoint,
            secp256r1n,
            secp256r1h,
            secp256r1Seed);

    /*
     * secp521r1 - (NIST P-521)
     */
    // p = 2^521 - 1
    static final BigInteger secp521r1P = new BigInteger(
            "6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151");

    // a = -3, b = 051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00
    static final ECCurve secp521r1Curve = new ECCurve.Fp(secp521r1P,
            new BigInteger("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057148"),
            new BigInteger("051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16));

    // x = c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66
    static final ECFieldElement secp521r1x = new ECFieldElement.Fp(
        secp521r1P,
        new BigInteger("c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16));

    // y = 11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650
    static final ECFieldElement secp521r1y = new ECFieldElement.Fp(
        secp521r1P,
        new BigInteger("11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16));

    static final ECPoint secp521r1BasePoint = new ECPoint.Fp(
//        secp521r1Curve, secp521r1x, secp521r1y);
        secp521r1Curve, secp521r1x, secp521r1y, false);

    static final BigInteger secp521r1n = new BigInteger("6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449");

    static final BigInteger secp521r1h = new BigInteger("1");

//    static final byte[] secp521r1Seed = (Hex.decode("d09e8800291cb85396cc6717393284aaa0da64ba"));
    static final byte[] secp521r1Seed = null;

    static final X9ECParameters secp521r1 = new X9ECParameters(
            secp521r1Curve,
            secp521r1BasePoint,
            secp521r1n,
            secp521r1h,
            secp521r1Seed);

    /*
     * sect163r1 (NIST B-163)
     */
    // m = 163, k1 = 3, k2 = 6, k3 = 7
    static final int sect163r1m = 163;
    static final int sect163r1k1 = 3;
    static final int sect163r1k2 = 6;
    static final int sect163r1k3 = 7;

    // a = 1
    static final BigInteger sect163r1a = BigInteger.ONE; 

    // b = 20a601907b8c953ca1481eb10512f78744a3205fd
    static final BigInteger sect163r1b = new BigInteger("20a601907b8c953ca1481eb10512f78744a3205fd", 16); 
    
    static final ECCurve sect163r1Curve = new ECCurve.F2m(sect163r1m, sect163r1k1, sect163r1k2, sect163r1k3, sect163r1a, sect163r1b);

    // x = 3f0eba16286a2d57ea0991168d4994637e8343e36
    static final ECFieldElement sect163r1x = new ECFieldElement.F2m(
        sect163r1m, sect163r1k1, sect163r1k2, sect163r1k3,
        new BigInteger("3f0eba16286a2d57ea0991168d4994637e8343e36", 16));

    // y = 0d51fbc6c71a0094fa2cdd545b11c5c0c797324f1
    static final ECFieldElement sect163r1y = new ECFieldElement.F2m(
        sect163r1m, sect163r1k1, sect163r1k2, sect163r1k3,
        new BigInteger("0d51fbc6c71a0094fa2cdd545b11c5c0c797324f1", 16));

    static final ECPoint sect163r1BasePoint = new ECPoint.F2m(
            sect163r1Curve, sect163r1x, sect163r1y);

    static final BigInteger sect163r1n = new BigInteger("5846006549323611672814742442876390689256843201587");

    static final BigInteger sect163r1h = new BigInteger("2");

    static final byte[] sect163r1Seed = null;
    
    static final X9ECParameters sect163r1 = new X9ECParameters(
            sect163r1Curve,
            sect163r1BasePoint,
            sect163r1n,
            sect163r1h,
            sect163r1Seed);

    /*
     * sect409r1 (NIST - B-409)
     */
    // m = 409, k1 = 87, k2 = 0, k3 = 0
    static final int sect409r1m = 409;
    static final int sect409r1k1 = 87;
    static final int sect409r1k2 = 0;
    static final int sect409r1k3 = 0;

    // a = 1
    static final BigInteger sect409r1a = BigInteger.ONE; 

    // b = 21a5c2c8ee9feb5c4b9a753b7b476b7fd6422ef1f3dd674761fa99d6ac27c8a9a197b272822f6cd57a55aa4f50ae317b13545f
    static final BigInteger sect409r1b = new BigInteger("21a5c2c8ee9feb5c4b9a753b7b476b7fd6422ef1f3dd674761fa99d6ac27c8a9a197b272822f6cd57a55aa4f50ae317b13545f", 16); 

    static final ECCurve sect409r1Curve = new ECCurve.F2m(sect409r1m, sect409r1k1, sect409r1k2, sect409r1k3, sect409r1a, sect409r1b);

    // x = 15d4860d088ddb3496b0c6064756260441cde4af1771d4db01ffe5b34e59703dc255a868a1180515603aeab60794e54bb7996a7
    static final ECFieldElement sect409r1x = new ECFieldElement.F2m(
            sect409r1m, sect409r1k1, sect409r1k2, sect409r1k3,
        new BigInteger("15d4860d088ddb3496b0c6064756260441cde4af1771d4db01ffe5b34e59703dc255a868a1180515603aeab60794e54bb7996a7", 16));

    // y = 61b1cfab6be5f32bbfa78324ed106a7636b9c5a7bd198d0158aa4f5488d08f38514f1fdf4b4f40d2181b3681c364ba0273c706
    static final ECFieldElement sect409r1y = new ECFieldElement.F2m(
            sect409r1m, sect409r1k1, sect409r1k2, sect409r1k3,
        new BigInteger("61b1cfab6be5f32bbfa78324ed106a7636b9c5a7bd198d0158aa4f5488d08f38514f1fdf4b4f40d2181b3681c364ba0273c706", 16));

    static final ECPoint sect409r1BasePoint = new ECPoint.F2m(
            sect409r1Curve, sect409r1x, sect409r1y);

    static final BigInteger sect409r1n = new BigInteger("661055968790248598951915308032771039828404682964281219284648798304157774827374805208143723762179110965979867288366567526771");

    static final BigInteger sect409r1h = new BigInteger("2");

    static final byte[] sect409r1Seed = null;
    
    static final X9ECParameters sect409r1 = new X9ECParameters(
            sect409r1Curve,
            sect409r1BasePoint,
            sect409r1n,
            sect409r1h,
            sect409r1Seed);
    
    static final Hashtable objIds = new Hashtable();
    static final Hashtable curves = new Hashtable();
    static final Hashtable names = new Hashtable();

    static
    {
        objIds.put("sect409r1", SECObjectIdentifiers.sect409r1);       
        objIds.put("sect163r1", SECObjectIdentifiers.sect163r1);       
        objIds.put("secp521r1", SECObjectIdentifiers.secp521r1);       
        objIds.put("secp256r1", SECObjectIdentifiers.secp256r1);   
        objIds.put("secp224r1", SECObjectIdentifiers.secp224r1); 

        names.put(SECObjectIdentifiers.sect409r1, "sect409r1");       
        names.put(SECObjectIdentifiers.sect163r1, "sect163r1");       
        names.put(SECObjectIdentifiers.secp521r1, "secp521r1");       
        names.put(SECObjectIdentifiers.secp256r1, "secp256r1"); 
        names.put(SECObjectIdentifiers.secp224r1, "secp224r1");

        curves.put(SECObjectIdentifiers.sect409r1, sect409r1);       
        curves.put(SECObjectIdentifiers.sect163r1, sect163r1);       
        curves.put(SECObjectIdentifiers.secp521r1, secp521r1); 
        curves.put(SECObjectIdentifiers.secp256r1, secp256r1);
        curves.put(SECObjectIdentifiers.secp224r1, secp224r1);             
    }
    
    public static X9ECParameters getByName(
        String  name)
    {
        DERObjectIdentifier oid = (DERObjectIdentifier)objIds.get(name.toLowerCase());

        if (oid != null)
        {
            return (X9ECParameters)curves.get(oid);
        }

        return null;
    }

    /**
     * return the X9ECParameters object for the named curve represented by
     * the passed in object identifier. Null if the curve isn't present.
     *
     * @param oid an object identifier representing a named curve, if present.
     */
    public static X9ECParameters getByOID(
        DERObjectIdentifier  oid)
    {
        return (X9ECParameters)curves.get(oid);
    }

    /**
     * return the object identifier signified by the passed in name. Null
     * if there is no object identifier associated with name.
     *
     * @return the object identifier associated with name, if present.
     */
    public static DERObjectIdentifier getOID(
        String  name)
    {
        return (DERObjectIdentifier)objIds.get(name);
    }

    /**
     * return the named curve name represented by the given object identifier.
     */
    public static String getName(
        DERObjectIdentifier  oid)
    {
        return (String)names.get(oid);
    }

    /**
     * returns an enumeration containing the name strings for curves
     * contained in this structure.
     */
    public static Enumeration getNames()
    {
        return objIds.keys();
    }
}
