package org.bouncycastle.asn1.sec;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECParametersHolder;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Hashtable;

public class SECNamedCurves
{
    private static BigInteger fromHex(
        String hex)
    {
        // TODO Figure out if one is faster?
        return new BigInteger(hex, 16);
        //return new BigInteger(1, Hex.decode(hex));
    }

    /*
     * secp112r1
     */
    static X9ECParametersHolder secp112r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            // p = (2^128 - 3) / 76439
            BigInteger p = fromHex("DB7C2ABF62E35E668076BEAD208B");
            BigInteger a = fromHex("DB7C2ABF62E35E668076BEAD2088");
            BigInteger b = fromHex("659EF8BA043916EEDE8911702B22");
            byte[] S = Hex.decode("00F50B028E4D696E676875615175290472783FB1");
            BigInteger n = fromHex("DB7C2ABF62E35E7628DFAC6561C5");
            BigInteger h = BigInteger.valueOf(1);

            ECCurve curve = new ECCurve.Fp(p, a, b);
            //ECPoint G = curve.decodePoint(Hex.decode("02"
            //+ "09487239995A5EE76B55F9C2F098"));
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "09487239995A5EE76B55F9C2F098"
                + "A89CE5AF8724C0A23E0E0FF77500"));

            return new X9ECParameters(curve, G, n, h, S);
        }
    };

    /*
     * secp112r2
     */
    static X9ECParametersHolder secp112r2 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            // p = (2^128 - 3) / 76439
            BigInteger p = fromHex("DB7C2ABF62E35E668076BEAD208B");
            BigInteger a = fromHex("6127C24C05F38A0AAAF65C0EF02C");
            BigInteger b = fromHex("51DEF1815DB5ED74FCC34C85D709");
            byte[] S = Hex.decode("002757A1114D696E6768756151755316C05E0BD4");
            BigInteger n = fromHex("36DF0AAFD8B8D7597CA10520D04B");
            BigInteger h = BigInteger.valueOf(4);

            ECCurve curve = new ECCurve.Fp(p, a, b);
            //ECPoint G = curve.decodePoint(Hex.decode("03"
            //+ "4BA30AB5E892B4E1649DD0928643"));
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "4BA30AB5E892B4E1649DD0928643"
                + "ADCD46F5882E3747DEF36E956E97"));

            return new X9ECParameters(curve, G, n, h, S);
        }
    };

    /*
     * secp128r1
     */
    static X9ECParametersHolder secp128r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            // p = 2^128 - 2^97 - 1
            BigInteger p = fromHex("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF");
            BigInteger a = fromHex("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC");
            BigInteger b = fromHex("E87579C11079F43DD824993C2CEE5ED3");
            byte[] S = Hex.decode("000E0D4D696E6768756151750CC03A4473D03679");
            BigInteger n = fromHex("FFFFFFFE0000000075A30D1B9038A115");
            BigInteger h = BigInteger.valueOf(1);

            ECCurve curve = new ECCurve.Fp(p, a, b);
            //ECPoint G = curve.decodePoint(Hex.decode("03"
            //+ "161FF7528B899B2D0C28607CA52C5B86"));
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "161FF7528B899B2D0C28607CA52C5B86"
                + "CF5AC8395BAFEB13C02DA292DDED7A83"));

            return new X9ECParameters(curve, G, n, h, S);
        }
    };

    /*
     * secp128r2
     */
    static X9ECParametersHolder secp128r2 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            // p = 2^128 - 2^97 - 1
            BigInteger p = fromHex("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF");
            BigInteger a = fromHex("D6031998D1B3BBFEBF59CC9BBFF9AEE1");
            BigInteger b = fromHex("5EEEFCA380D02919DC2C6558BB6D8A5D");
            byte[] S = Hex.decode("004D696E67687561517512D8F03431FCE63B88F4");
            BigInteger n = fromHex("3FFFFFFF7FFFFFFFBE0024720613B5A3");
            BigInteger h = BigInteger.valueOf(4);

            ECCurve curve = new ECCurve.Fp(p, a, b);
            //ECPoint G = curve.decodePoint(Hex.decode("02"
            //+ "7B6AA5D85E572983E6FB32A7CDEBC140"));
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "7B6AA5D85E572983E6FB32A7CDEBC140"
                + "27B6916A894D3AEE7106FE805FC34B44"));

            return new X9ECParameters(curve, G, n, h, S);
        }
    };

    /*
     * secp160k1
     */
    static X9ECParametersHolder secp160k1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            // p = 2^160 - 2^32 - 2^14 - 2^12 - 2^9 - 2^8 - 2^7 - 2^3 - 2^2 - 1
            BigInteger p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73");
            BigInteger a = BigInteger.ZERO;
            BigInteger b = BigInteger.valueOf(7);
            byte[] S = null;
            BigInteger n = fromHex("0100000000000000000001B8FA16DFAB9ACA16B6B3");
            BigInteger h = BigInteger.valueOf(1);

            ECCurve curve = new ECCurve.Fp(p, a, b);
            //ECPoint G = curve.decodePoint(Hex.decode("02"
                //+ "3B4C382CE37AA192A4019E763036F4F5DD4D7EBB"));
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "3B4C382CE37AA192A4019E763036F4F5DD4D7EBB"
                + "938CF935318FDCED6BC28286531733C3F03C4FEE"));

            return new X9ECParameters(curve, G, n, h, S);
        }
    };

    /*
     * secp160r1
     */
    static X9ECParametersHolder secp160r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            // p = 2^160 - 2^31 - 1
            BigInteger p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF");
            BigInteger a = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC");
            BigInteger b = fromHex("1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45");
            byte[] S = Hex.decode("1053CDE42C14D696E67687561517533BF3F83345");
            BigInteger n = fromHex("0100000000000000000001F4C8F927AED3CA752257");
            BigInteger h = BigInteger.valueOf(1);

            ECCurve curve = new ECCurve.Fp(p, a, b);
            //ECPoint G = curve.decodePoint(Hex.decode("02"
                //+ "4A96B5688EF573284664698968C38BB913CBFC82"));
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "4A96B5688EF573284664698968C38BB913CBFC82"
                + "23A628553168947D59DCC912042351377AC5FB32"));

            return new X9ECParameters(curve, G, n, h, S);
        }
    };

    /*
     * secp160r2
     */
    static X9ECParametersHolder secp160r2 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            // p = 2^160 - 2^32 - 2^14 - 2^12 - 2^9 - 2^8 - 2^7 - 2^3 - 2^2 - 1
            BigInteger p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73");
            BigInteger a = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC70");
            BigInteger b = fromHex("B4E134D3FB59EB8BAB57274904664D5AF50388BA");
            byte[] S = Hex.decode("B99B99B099B323E02709A4D696E6768756151751");
            BigInteger n = fromHex("0100000000000000000000351EE786A818F3A1A16B");
            BigInteger h = BigInteger.valueOf(1);

            ECCurve curve = new ECCurve.Fp(p, a, b);
            //ECPoint G = curve.decodePoint(Hex.decode("02"
            //+ "52DCB034293A117E1F4FF11B30F7199D3144CE6D"));
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "52DCB034293A117E1F4FF11B30F7199D3144CE6D"
                + "FEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E"));

            return new X9ECParameters(curve, G, n, h, S);
        }
    };

    /*
     * secp192k1
     */
    static X9ECParametersHolder secp192k1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            // p = 2^192 - 2^32 - 2^12 - 2^8 - 2^7 - 2^6 - 2^3 - 1
            BigInteger p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37");
            BigInteger a = BigInteger.ZERO;
            BigInteger b = BigInteger.valueOf(3);
            byte[] S = null;
            BigInteger n = fromHex("FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D");
            BigInteger h = BigInteger.valueOf(1);

            ECCurve curve = new ECCurve.Fp(p, a, b);
            //ECPoint G = curve.decodePoint(Hex.decode("03"
            //+ "DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D"));
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D"
                + "9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D"));

            return new X9ECParameters(curve, G, n, h, S);
        }
    };

    /*
     * secp192r1
     */
    static X9ECParametersHolder secp192r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            // p = 2^192 - 2^64 - 1
            BigInteger p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF");
            BigInteger a = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC");
            BigInteger b = fromHex("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1");
            byte[] S = Hex.decode("3045AE6FC8422F64ED579528D38120EAE12196D5");
            BigInteger n = fromHex("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831");
            BigInteger h = BigInteger.valueOf(1);

            ECCurve curve = new ECCurve.Fp(p, a, b);
            //ECPoint G = curve.decodePoint(Hex.decode("03"
            //+ "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012"));
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012"
                + "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811"));

            return new X9ECParameters(curve, G, n, h, S);
        }
    };

    /*
     * secp224k1
     */
    static X9ECParametersHolder secp224k1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            // p = 2^224 - 2^32 - 2^12 - 2^11 - 2^9 - 2^7 - 2^4 - 2 - 1
            BigInteger p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D");
            BigInteger a = BigInteger.ZERO;
            BigInteger b = BigInteger.valueOf(5);
            byte[] S = null;
            BigInteger n = fromHex("010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7");
            BigInteger h = BigInteger.valueOf(1);

            ECCurve curve = new ECCurve.Fp(p, a, b);
            //ECPoint G = curve.decodePoint(Hex.decode("03"
            //+ "A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C"));
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C"
                + "7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5"));

            return new X9ECParameters(curve, G, n, h, S);
        }
    };

    /*
     * secp224r1
     */
    static X9ECParametersHolder secp224r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            // p = 2^224 - 2^96 + 1
            BigInteger p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001");
            BigInteger a = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE");
            BigInteger b = fromHex("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4");
            byte[] S = Hex.decode("BD71344799D5C7FCDC45B59FA3B9AB8F6A948BC5");
            BigInteger n = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D");
            BigInteger h = BigInteger.valueOf(1);

            ECCurve curve = new ECCurve.Fp(p, a, b);
            //ECPoint G = curve.decodePoint(Hex.decode("02"
            //+ "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21"));
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21"
                + "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34"));

            return new X9ECParameters(curve, G, n, h, S);
        }
    };

    /*
     * secp256k1
     */
    static X9ECParametersHolder secp256k1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            // p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
            BigInteger p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
            BigInteger a = BigInteger.ZERO;
            BigInteger b = BigInteger.valueOf(7);
            byte[] S = null;
            BigInteger n = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
            BigInteger h = BigInteger.valueOf(1);

            ECCurve curve = new ECCurve.Fp(p, a, b);
            //ECPoint G = curve.decodePoint(Hex.decode("02"
            //+ "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"));
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
                + "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"));

            return new X9ECParameters(curve, G, n, h, S);
        }
    };

    /*
     * secp256r1
     */
    static X9ECParametersHolder secp256r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            // p = 2^224 (2^32 - 1) + 2^192 + 2^96 - 1
            BigInteger p = fromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
            BigInteger a = fromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
            BigInteger b = fromHex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
            byte[] S = Hex.decode("C49D360886E704936A6678E1139D26B7819F7E90");
            BigInteger n = fromHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
            BigInteger h = BigInteger.valueOf(1);

            ECCurve curve = new ECCurve.Fp(p, a, b);
            //ECPoint G = curve.decodePoint(Hex.decode("03"
            //+ "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"));
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
                + "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"));

            return new X9ECParameters(curve, G, n, h, S);
        }
    };

    /*
     * secp384r1
     */
    static X9ECParametersHolder secp384r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            // p = 2^384 - 2^128 - 2^96 + 2^32 - 1
            BigInteger p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF");
            BigInteger a = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC");
            BigInteger b = fromHex("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF");
            byte[] S = Hex.decode("A335926AA319A27A1D00896A6773A4827ACDAC73");
            BigInteger n = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973");
            BigInteger h = BigInteger.valueOf(1);

            ECCurve curve = new ECCurve.Fp(p, a, b);
            //ECPoint G = curve.decodePoint(Hex.decode("03"
            //+ "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"));
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"
                + "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"));

            return new X9ECParameters(curve, G, n, h, S);
        }
    };

    /*
     * secp521r1
     */
    static X9ECParametersHolder secp521r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            // p = 2^521 - 1
            BigInteger p = fromHex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
            BigInteger a = fromHex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC");
            BigInteger b = fromHex("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00");
            byte[] S = Hex.decode("D09E8800291CB85396CC6717393284AAA0DA64BA");
            BigInteger n = fromHex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409");
            BigInteger h = BigInteger.valueOf(1);

            ECCurve curve = new ECCurve.Fp(p, a, b);
            //ECPoint G = curve.decodePoint(Hex.decode("02"
            //+ "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"));
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"
                + "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"));

            return new X9ECParameters(curve, G, n, h, S);
        }
    };
    

    /*
     * sect163r2 (NIST B-163)
     */
    static X9ECParametersHolder sect163r2 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            // m = 163, k1 = 3, k2 = 6, k3 = 7
            int sect163r2m = 163;
            int sect163r2k1 = 3;
            int sect163r2k2 = 6;
            int sect163r2k3 = 7;

            // a = 1
            BigInteger sect163r2a = ECConstants.ONE;

            // b = 20a601907b8c953ca1481eb10512f78744a3205fd
            BigInteger sect163r2b = new BigInteger("20a601907b8c953ca1481eb10512f78744a3205fd", 16);

            ECCurve sect163r2Curve = new ECCurve.F2m(sect163r2m, sect163r2k1, sect163r2k2, sect163r2k3, sect163r2a, sect163r2b);

            // x = 3f0eba16286a2d57ea0991168d4994637e8343e36
            ECFieldElement sect163r2x = new ECFieldElement.F2m(
                sect163r2m, sect163r2k1, sect163r2k2, sect163r2k3,
                new BigInteger("3f0eba16286a2d57ea0991168d4994637e8343e36", 16));

            // y = 0d51fbc6c71a0094fa2cdd545b11c5c0c797324f1
            ECFieldElement sect163r2y = new ECFieldElement.F2m(
                sect163r2m, sect163r2k1, sect163r2k2, sect163r2k3,
                new BigInteger("0d51fbc6c71a0094fa2cdd545b11c5c0c797324f1", 16));

            ECPoint sect163r2BasePoint = new ECPoint.F2m(
                sect163r2Curve, sect163r2x, sect163r2y, false);

            BigInteger sect163r2n = new BigInteger("5846006549323611672814742442876390689256843201587");

            BigInteger sect163r2h = new BigInteger("2");

            byte[] sect163r2Seed = null;

            return new X9ECParameters(
                sect163r2Curve,
                sect163r2BasePoint,
                sect163r2n,
                sect163r2h,
                sect163r2Seed);
        }
    };

    /*
     * sect233r1 (NIST B-233)
     */
    static X9ECParametersHolder sect233r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            // m = 233, k1 = 74, k2 = 0, k3 = 0
            int sect233r1m = 233;
            int sect233r1k1 = 74;
            int sect233r1k2 = 0;
            int sect233r1k3 = 0;

            // a = 1
            BigInteger sect233r1a = ECConstants.ONE;

            // b = 066647ede6c332c7f8c0923bb58213b333b20e9ce4281fe115f7d8f90ad
            BigInteger sect233r1b = new BigInteger("066647ede6c332c7f8c0923bb58213b333b20e9ce4281fe115f7d8f90ad", 16);

            ECCurve sect233r1Curve = new ECCurve.F2m(sect233r1m, sect233r1k1, sect233r1k2, sect233r1k3, sect233r1a, sect233r1b);

            // x = 0fac9dfcbac8313bb2139f1bb755fef65bc391f8b36f8f8eb7371fd558b
            ECFieldElement sect233r1x = new ECFieldElement.F2m(
                sect233r1m, sect233r1k1, sect233r1k2, sect233r1k3,
                new BigInteger("0fac9dfcbac8313bb2139f1bb755fef65bc391f8b36f8f8eb7371fd558b", 16));

            // y = 1006a08a41903350678e58528bebf8a0beff867a7ca36716f7e01f81052
            ECFieldElement sect233r1y = new ECFieldElement.F2m(
                sect233r1m, sect233r1k1, sect233r1k2, sect233r1k3,
                new BigInteger("1006a08a41903350678e58528bebf8a0beff867a7ca36716f7e01f81052", 16));

            ECPoint sect233r1BasePoint = new ECPoint.F2m(
                sect233r1Curve, sect233r1x, sect233r1y, false);

            BigInteger sect233r1n = new BigInteger("6901746346790563787434755862277025555839812737345013555379383634485463");

            BigInteger sect233r1h = new BigInteger("2");

            byte[] sect233r1Seed = null;

            return new X9ECParameters(
                sect233r1Curve,
                sect233r1BasePoint,
                sect233r1n,
                sect233r1h,
                sect233r1Seed);
        }
    };


    /*
     * sect283r1 (NIST B-283)
     */
    static X9ECParametersHolder sect283r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            // m = 283, k1 = 5, k2 = 7, k3 = 12
            int sect283r1m = 283;
            int sect283r1k1 = 5;
            int sect283r1k2 = 7;
            int sect283r1k3 = 12;

            // a = 1
            BigInteger sect283r1a = ECConstants.ONE;

            // b = 27b680ac8b8596da5a4af8a19a0303fca97fd7645309fa2a581485af6263e313b79a2f5
            BigInteger sect283r1b = new BigInteger("27b680ac8b8596da5a4af8a19a0303fca97fd7645309fa2a581485af6263e313b79a2f5", 16);

            ECCurve sect283r1Curve = new ECCurve.F2m(sect283r1m, sect283r1k1, sect283r1k2, sect283r1k3, sect283r1a, sect283r1b);

            // x = 5f939258db7dd90e1934f8c70b0dfec2eed25b8557eac9c80e2e198f8cdbecd86b12053
            ECFieldElement sect283r1x = new ECFieldElement.F2m(
                sect283r1m, sect283r1k1, sect283r1k2, sect283r1k3,
                new BigInteger("5f939258db7dd90e1934f8c70b0dfec2eed25b8557eac9c80e2e198f8cdbecd86b12053", 16));

            // y = 3676854fe24141cb98fe6d4b20d02b4516ff702350eddb0826779c813f0df45be8112f4
            ECFieldElement sect283r1y = new ECFieldElement.F2m(
                sect283r1m, sect283r1k1, sect283r1k2, sect283r1k3,
                new BigInteger("3676854fe24141cb98fe6d4b20d02b4516ff702350eddb0826779c813f0df45be8112f4", 16));

            ECPoint sect283r1BasePoint = new ECPoint.F2m(
                sect283r1Curve, sect283r1x, sect283r1y, false);

            BigInteger sect283r1n = new BigInteger("7770675568902916283677847627294075626569625924376904889109196526770044277787378692871");

            BigInteger sect283r1h = new BigInteger("2");

            byte[] sect283r1Seed = null;

            return new X9ECParameters(
                sect283r1Curve,
                sect283r1BasePoint,
                sect283r1n,
                sect283r1h,
                sect283r1Seed);
        }
    };


    /*
     * sect409r1 (NIST - B-409)
     */
    static X9ECParametersHolder sect409r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            // m = 409, k1 = 87, k2 = 0, k3 = 0
            int sect409r1m = 409;
            int sect409r1k1 = 87;
            int sect409r1k2 = 0;
            int sect409r1k3 = 0;

            // a = 1
            BigInteger sect409r1a = ECConstants.ONE;

            // b = 21a5c2c8ee9feb5c4b9a753b7b476b7fd6422ef1f3dd674761fa99d6ac27c8a9a197b272822f6cd57a55aa4f50ae317b13545f
            BigInteger sect409r1b = new BigInteger("21a5c2c8ee9feb5c4b9a753b7b476b7fd6422ef1f3dd674761fa99d6ac27c8a9a197b272822f6cd57a55aa4f50ae317b13545f", 16);

            ECCurve sect409r1Curve = new ECCurve.F2m(sect409r1m, sect409r1k1, sect409r1k2, sect409r1k3, sect409r1a, sect409r1b);

            // x = 15d4860d088ddb3496b0c6064756260441cde4af1771d4db01ffe5b34e59703dc255a868a1180515603aeab60794e54bb7996a7
            ECFieldElement sect409r1x = new ECFieldElement.F2m(
                sect409r1m, sect409r1k1, sect409r1k2, sect409r1k3,
                new BigInteger("15d4860d088ddb3496b0c6064756260441cde4af1771d4db01ffe5b34e59703dc255a868a1180515603aeab60794e54bb7996a7", 16));

            // y = 61b1cfab6be5f32bbfa78324ed106a7636b9c5a7bd198d0158aa4f5488d08f38514f1fdf4b4f40d2181b3681c364ba0273c706
            ECFieldElement sect409r1y = new ECFieldElement.F2m(
                sect409r1m, sect409r1k1, sect409r1k2, sect409r1k3,
                new BigInteger("61b1cfab6be5f32bbfa78324ed106a7636b9c5a7bd198d0158aa4f5488d08f38514f1fdf4b4f40d2181b3681c364ba0273c706", 16));

            ECPoint sect409r1BasePoint = new ECPoint.F2m(
                sect409r1Curve, sect409r1x, sect409r1y, false);

            BigInteger sect409r1n = new BigInteger("661055968790248598951915308032771039828404682964281219284648798304157774827374805208143723762179110965979867288366567526771");

            BigInteger sect409r1h = new BigInteger("2");

            byte[] sect409r1Seed = null;

            return new X9ECParameters(
                sect409r1Curve,
                sect409r1BasePoint,
                sect409r1n,
                sect409r1h,
                sect409r1Seed);
        }
    };


    /*
     * sect571r1 (NIST - B-571)
     */
    static X9ECParametersHolder sect571r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            // m = 571, k1 = 2, k2 = 5, k3 = 10
            int sect571r1m = 571;
            int sect571r1k1 = 2;
            int sect571r1k2 = 5;
            int sect571r1k3 = 10;

            // a = 1
            BigInteger sect571r1a = ECConstants.ONE;

            // b = 2f40e7e2221f295de297117b7f3d62f5c6a97ffcb8ceff1cd6ba8ce4a9a18ad84ffabbd8efa59332be7ad6756a66e294afd185a78ff12aa520e4de739baca0c7ffeff7f2955727a
            BigInteger sect571r1b = new BigInteger("2f40e7e2221f295de297117b7f3d62f5c6a97ffcb8ceff1cd6ba8ce4a9a18ad84ffabbd8efa59332be7ad6756a66e294afd185a78ff12aa520e4de739baca0c7ffeff7f2955727a", 16);

            ECCurve sect571r1Curve = new ECCurve.F2m(sect571r1m, sect571r1k1, sect571r1k2, sect571r1k3, sect571r1a, sect571r1b);

            // x = 303001d34b856296c16c0d40d3cd7750a93d1d2955fa80aa5f40fc8db7b2abdbde53950f4c0d293cdd711a35b67fb1499ae60038614f1394abfa3b4c850d927e1e7769c8eec2d19
            ECFieldElement sect571r1x = new ECFieldElement.F2m(
                sect571r1m, sect571r1k1, sect571r1k2, sect571r1k3,
                new BigInteger("303001d34b856296c16c0d40d3cd7750a93d1d2955fa80aa5f40fc8db7b2abdbde53950f4c0d293cdd711a35b67fb1499ae60038614f1394abfa3b4c850d927e1e7769c8eec2d19", 16));

            // y = 37bf27342da639b6dccfffeb73d69d78c6c27a6009cbbca1980f8533921e8a684423e43bab08a576291af8f461bb2a8b3531d2f0485c19b16e2f1516e23dd3c1a4827af1b8ac15b
            ECFieldElement sect571r1y = new ECFieldElement.F2m(
                sect571r1m, sect571r1k1, sect571r1k2, sect571r1k3,
                new BigInteger("37bf27342da639b6dccfffeb73d69d78c6c27a6009cbbca1980f8533921e8a684423e43bab08a576291af8f461bb2a8b3531d2f0485c19b16e2f1516e23dd3c1a4827af1b8ac15b", 16));

            ECPoint sect571r1BasePoint = new ECPoint.F2m(
                sect571r1Curve, sect571r1x, sect571r1y, false);

            BigInteger sect571r1n = new BigInteger("3864537523017258344695351890931987344298927329706434998657235251451519142289560424536143999389415773083133881121926944486246872462816813070234528288303332411393191105285703");

            BigInteger sect571r1h = new BigInteger("2");

            byte[] sect571r1Seed = null;

            return new X9ECParameters(
                sect571r1Curve,
                sect571r1BasePoint,
                sect571r1n,
                sect571r1h,
                sect571r1Seed);
        }
    };


    static final Hashtable objIds = new Hashtable();
    static final Hashtable curves = new Hashtable();
    static final Hashtable names = new Hashtable();

    static void defineCurve(String name, DERObjectIdentifier oid, X9ECParametersHolder holder)
    {
        objIds.put(name, oid);
        names.put(oid, name);
        curves.put(oid, holder);
    }

    static
    {
        defineCurve("secp112r1", SECObjectIdentifiers.secp112r1, secp112r1);
        defineCurve("secp112r2", SECObjectIdentifiers.secp112r2, secp112r2);
        defineCurve("secp128r1", SECObjectIdentifiers.secp128r1, secp128r1);
        defineCurve("secp128r2", SECObjectIdentifiers.secp128r2, secp128r2);
        defineCurve("secp160k1", SECObjectIdentifiers.secp160k1, secp160k1);
        defineCurve("secp160r1", SECObjectIdentifiers.secp160r1, secp160r1);
        defineCurve("secp160r2", SECObjectIdentifiers.secp160r2, secp160r2);
        defineCurve("secp192k1", SECObjectIdentifiers.secp192k1, secp192k1);
        defineCurve("secp192r1", SECObjectIdentifiers.secp192r1, secp192r1);
        defineCurve("secp224k1", SECObjectIdentifiers.secp224k1, secp224k1); 
        defineCurve("secp224r1", SECObjectIdentifiers.secp224r1, secp224r1); 
        defineCurve("secp256k1", SECObjectIdentifiers.secp256k1, secp256k1); 
        defineCurve("secp256r1", SECObjectIdentifiers.secp256r1, secp256r1); 
        defineCurve("secp384r1", SECObjectIdentifiers.secp384r1, secp384r1); 
        defineCurve("secp521r1", SECObjectIdentifiers.secp521r1, secp521r1); 

//        defineCurve("sect113r1", SECObjectIdentifiers.sect113r1, sect113r1);
//        defineCurve("sect113r2", SECObjectIdentifiers.sect113r2, sect113r2);
//        defineCurve("sect131r1", SECObjectIdentifiers.sect131r1, sect131r1);
//        defineCurve("sect131r2", SECObjectIdentifiers.sect131r2, sect131r2);
//        defineCurve("sect163k1", SECObjectIdentifiers.sect163k1, sect163k1);
//        defineCurve("sect163r1", SECObjectIdentifiers.sect163r1, sect163r1);
        defineCurve("sect163r2", SECObjectIdentifiers.sect163r2, sect163r2);
//        defineCurve("sect193r1", SECObjectIdentifiers.sect193r1, sect193r1);
//        defineCurve("sect193r2", SECObjectIdentifiers.sect193r2, sect193r2);
//        defineCurve("sect233k1", SECObjectIdentifiers.sect233k1, sect233k1);
        defineCurve("sect233r1", SECObjectIdentifiers.sect233r1, sect233r1);
//        defineCurve("sect239k1", SECObjectIdentifiers.sect239k1, sect239k1);
//        defineCurve("sect283k1", SECObjectIdentifiers.sect283k1, sect283k1);
        defineCurve("sect283r1", SECObjectIdentifiers.sect283r1, sect283r1);
//        defineCurve("sect409k1", SECObjectIdentifiers.sect409k1, sect409k1);
        defineCurve("sect409r1", SECObjectIdentifiers.sect409r1, sect409r1);
//        defineCurve("sect571k1", SECObjectIdentifiers.sect571k1, sect571k1);
        defineCurve("sect571r1", SECObjectIdentifiers.sect571r1, sect571r1); 
    }

    public static X9ECParameters getByName(
        String name)
    {
        DERObjectIdentifier oid = (DERObjectIdentifier)objIds.get(Strings.toLowerCase(name));

        if (oid != null)
        {
            return getByOID(oid);
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
        DERObjectIdentifier oid)
    {
        X9ECParametersHolder holder = (X9ECParametersHolder)curves.get(oid);

        if (holder != null)
        {
            return holder.getParameters();
        }

        return null;
    }

    /**
     * return the object identifier signified by the passed in name. Null
     * if there is no object identifier associated with name.
     *
     * @return the object identifier associated with name, if present.
     */
    public static DERObjectIdentifier getOID(
        String name)
    {
        return (DERObjectIdentifier)objIds.get(Strings.toLowerCase(name));
    }

    /**
     * return the named curve name represented by the given object identifier.
     */
    public static String getName(
        DERObjectIdentifier oid)
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
