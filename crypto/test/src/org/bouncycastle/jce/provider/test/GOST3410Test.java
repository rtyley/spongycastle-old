package org.bouncycastle.jce.provider.test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.jce.interfaces.GOST3410PrivateKey;
import org.bouncycastle.jce.interfaces.GOST3410PublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jce.spec.GOST3410ParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class GOST3410Test
    implements Test
{
    SecureRandom    random = new SecureRandom()
    {
        boolean firstLong = true;

        public long nextLong()
        {
            String x0 = "0x13DA8B9D";
            String c =  "0xA0E9DE4B";

            if (firstLong)
            {
                firstLong = false;
                return Long.decode(x0).longValue();
            }
            else
            {
                return Long.decode(c).longValue();
            }
        }

        public void nextBytes(byte[] bytes)
        {

            byte[] d = Hex.decode("41ab97857f42614355d32db0b1069f109a4da283676c7c53a68185b4");

            System.arraycopy(d, 0, bytes, bytes.length-d.length, d.length);
        }
    };

    private class ECGOST3410Test
        implements Test
    {
        BigInteger r = new BigInteger("29700980915817952874371204983938256990422752107994319651632687982059210933395");
        BigInteger s = new BigInteger("46959264877825372965922731380059061821746083849389763294914877353246631700866");

        SecureRandom    k = new SecureRandom()
        {
            public void nextBytes(byte[] bytes)
            {
                byte[] k = new BigInteger("53854137677348463731403841147996619241504003434302020712960838528893196233395").toByteArray();

                System.arraycopy(k, k.length-bytes.length, bytes, 0, bytes.length);
            }
        };

        public String getName()
        {
            return "ECGOST3410 Test";
        }

        public TestResult perform()
        {
            try
            {
                BigInteger mod_p = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564821041"); //p

                ECCurve curve = new ECCurve.Fp(
                    mod_p, // p
                    new BigInteger("7"), // a
                    new BigInteger("43308876546767276905765904595650931995942111794451039583252968842033849580414")); // b

                ECParameterSpec spec = new ECParameterSpec(
                    curve,
                        new ECPoint.Fp(curve,
                                       new ECFieldElement.Fp(mod_p,new BigInteger("2")), // x
                                       new ECFieldElement.Fp(mod_p,new BigInteger("4018974056539037503335449422937059775635739389905545080690979365213431566280"))), // y
                        new BigInteger("57896044618658097711785492504343953927082934583725450622380973592137631069619")); // q

                ECPrivateKeySpec priKey = new ECPrivateKeySpec(
                    new BigInteger("55441196065363246126355624130324183196576709222340016572108097750006097525544"), // d
                    spec);

                ECPublicKeySpec pubKey = new ECPublicKeySpec(
                        new ECPoint.Fp(curve,
                                       new ECFieldElement.Fp(mod_p, new BigInteger("57520216126176808443631405023338071176630104906313632182896741342206604859403")), // x
                                       new ECFieldElement.Fp(mod_p, new BigInteger("17614944419213781543809391949654080031942662045363639260709847859438286763994"))), // y
                    spec);

                Signature           sgr = Signature.getInstance("ECGOST3410", "BC");
                KeyFactory          f = KeyFactory.getInstance("ECGOST3410", "BC");
                PrivateKey          sKey = f.generatePrivate(priKey);
                PublicKey           vKey = f.generatePublic(pubKey);

                sgr.initSign(sKey, k);

                byte[] message = new byte[] { (byte)'a', (byte)'b', (byte)'c' };

                sgr.update(message);

                byte[]  sigBytes = sgr.sign();

                sgr.initVerify(vKey);

                sgr.update(message);

                if (!sgr.verify(sigBytes))
                {
                    return new SimpleTestResult(false, this.getName() + ": ECGOST3410 verification failed");
                }

                BigInteger[]  sig = decode(sigBytes);

                if (!r.equals(sig[0]))
                {
                    return new SimpleTestResult(false, getName()
                        + ": r component wrong." + System.getProperty("line.separator")
                        + " expecting: " + r + System.getProperty("line.separator")
                        + " got      : " + sig[0]);
                }

                if (!s.equals(sig[1]))
                {
                    return new SimpleTestResult(false, getName()
                        + ": s component wrong." + System.getProperty("line.separator")
                        + " expecting: " + s + System.getProperty("line.separator")
                        + " got      : " + sig[1]);
                }
            }
            catch (Exception e)
            {
                return new SimpleTestResult(false, this.getName() + ": exception - " + e.toString(), e);
            }

            return new SimpleTestResult(true, this.getName() + ": Okay");
        }
    }

    private class GenerationTest
        implements Test
    {
        public String getName()
        {
            return "GOST3410/ECGOST3410 Generation";
        }

        public TestResult perform()
        {
            try
            {
                Signature             s = Signature.getInstance("GOST3410", "BC");
                KeyPairGenerator      g = KeyPairGenerator.getInstance("GOST3410", "BC");
                byte[]                data = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
                GOST3410ParameterSpec gost3410P = new GOST3410ParameterSpec(CryptoProObjectIdentifiers.gostR3410_94_CryptoPro_A.getId());
                
                g.initialize(gost3410P, new SecureRandom());

                KeyPair p = g.generateKeyPair();

                PrivateKey  sKey = p.getPrivate();
                PublicKey   vKey = p.getPublic();

                s.initSign(sKey);

                s.update(data);

                byte[]  sigBytes = s.sign();

                s = Signature.getInstance("GOST3410", "BC");

                s.initVerify(vKey);

                s.update(data);

                if (!s.verify(sigBytes))
                {
                    return new SimpleTestResult(false, this.getName() + ": GOST3410 verification failed");
                }

                //
                // default iniialisation test
                //
                s = Signature.getInstance("GOST3410", "BC");
                g = KeyPairGenerator.getInstance("GOST3410", "BC");
                
                p = g.generateKeyPair();

                sKey = p.getPrivate();
                vKey = p.getPublic();

                s.initSign(sKey);

                s.update(data);

                sigBytes = s.sign();

                s = Signature.getInstance("GOST3410", "BC");

                s.initVerify(vKey);

                s.update(data);

                if (!s.verify(sigBytes))
                {
                    return new SimpleTestResult(false, this.getName() + ": GOST3410 verification failed");
                }

                //
                // encoded test
                //
                KeyFactory f = KeyFactory.getInstance("GOST3410", "BC");

                X509EncodedKeySpec  x509s = new X509EncodedKeySpec(vKey.getEncoded());
                GOST3410PublicKey   k1 = (GOST3410PublicKey)f.generatePublic(x509s);

                if (!k1.getY().equals(((GOST3410PublicKey)vKey).getY()))
                {
                    return new SimpleTestResult(false, this.getName() + ": public number not decoded properly");
                }

                PKCS8EncodedKeySpec  pkcs8 = new PKCS8EncodedKeySpec(sKey.getEncoded());
                GOST3410PrivateKey   k2 = (GOST3410PrivateKey)f.generatePrivate(pkcs8);

                if (!k2.getX().equals(((GOST3410PrivateKey)sKey).getX()))
                {
                    return new SimpleTestResult(false, this.getName() + ": private number not decoded properly");
                }
                
                //
                // ECGOST3410 generation test
                //
                s = Signature.getInstance("ECGOST3410", "BC");
                g = KeyPairGenerator.getInstance("ECGOST3410", "BC");

                BigInteger mod_p = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564821041"); //p

                ECCurve curve = new ECCurve.Fp(
                    mod_p, // p
                    new BigInteger("7"), // a
                    new BigInteger("43308876546767276905765904595650931995942111794451039583252968842033849580414")); // b

                ECParameterSpec ecSpec = new ECParameterSpec(
                        curve,
                            new ECPoint.Fp(curve,
                                           new ECFieldElement.Fp(mod_p,new BigInteger("2")), // x
                                           new ECFieldElement.Fp(mod_p,new BigInteger("4018974056539037503335449422937059775635739389905545080690979365213431566280"))), // y
                            new BigInteger("57896044618658097711785492504343953927082934583725450622380973592137631069619")); // q

                g.initialize(ecSpec, new SecureRandom());

                p = g.generateKeyPair();

                sKey = p.getPrivate();
                vKey = p.getPublic();

                s.initSign(sKey);

                s.update(data);

                sigBytes = s.sign();

                s = Signature.getInstance("ECGOST3410", "BC");

                s.initVerify(vKey);

                s.update(data);

                if (!s.verify(sigBytes))
                {
                    return new SimpleTestResult(false, this.getName() + ": ECGOST3410 verification failed");
                }
            }
            catch (Exception e)
            {
                return new SimpleTestResult(false, this.getName() + ": exception - " + e.toString(), e);
            }

            return new SimpleTestResult(true, this.getName() + ": Okay");
        }
    }

    private class ParametersTest
        implements Test
    {
        public String getName()
        {
            return "GOST3410 Parameters";
        }

        public TestResult perform()
        {
            try
            {
//                AlgorithmParameterGenerator a = AlgorithmParameterGenerator.getInstance("GOST3410", "BC");
//                a.init(512, random);
//                AlgorithmParameters params = a.generateParameters();
//
//                byte[] encodeParams = params.getEncoded();
//
//                AlgorithmParameters a2 = AlgorithmParameters.getInstance("GOST3410", "BC");
//                a2.init(encodeParams);
//
//                // a and a2 should be equivalent!
//                byte[] encodeParams_2 = a2.getEncoded();
//
//                if (!arrayEquals(encodeParams, encodeParams_2))
//                {
//                    return new SimpleTestResult(false, this.getName() + ": encode/decode parameters failed");
//                }

                GOST3410ParameterSpec gost3410P = new GOST3410ParameterSpec(CryptoProObjectIdentifiers.gostR3410_94_CryptoPro_B.getId());

                KeyPairGenerator    g = KeyPairGenerator.getInstance("GOST3410", "BC");
                g.initialize(gost3410P, new SecureRandom());
                KeyPair p = g.generateKeyPair();

                PrivateKey  sKey = p.getPrivate();
                PublicKey   vKey = p.getPublic();

                Signature           s = Signature.getInstance("GOST3410", "BC");
                byte[]              data = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };

                s.initSign(sKey);

                s.update(data);

                byte[]  sigBytes = s.sign();

                s = Signature.getInstance("GOST3410", "BC");

                s.initVerify(vKey);

                s.update(data);

                if (!s.verify(sigBytes))
                {
                    return new SimpleTestResult(false, this.getName() + ": GOST3410 verification failed");
                }
            }
            catch (Exception e)
            {
                return new SimpleTestResult(false, this.getName() + ": exception - " + e.toString(), e);
            }

            return new SimpleTestResult(true, this.getName() + ": Okay");
        }
    }

    Test tests[] =
    {
        new ECGOST3410Test(),
        new GenerationTest(),
        new ParametersTest()
    };

    private BigInteger[] decode(
        byte[]  encoding)
        throws IOException
    {
        byte[] r = new byte[32];
        byte[] s = new byte[32];

        for (int i = 0; i != 32; i ++)
        {
            s[i] = encoding[i];
        }

        for (int i = 0; i != 32; i ++)
        {
            r[i] = encoding[32 + i];
        }

        BigInteger[]            sig = new BigInteger[2];

        sig[0] = new BigInteger(1, r);
        sig[1] = new BigInteger(1, s);

        return sig;
    }

    private boolean arrayEquals(
        byte[]  a,
        byte[]  b)
    {
        if (a.length != b.length)
        {
            return false;
        }

        for (int i = 0; i != a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }

    public String getName()
    {
        return "GOST3410/ECGOST3410";
    }

    public TestResult perform()
    {
        for (int i = 0; i != tests.length; i++)
        {
            TestResult  result = tests[i].perform();

            if (!result.isSuccessful())
            {
                return result;
            }
        }

        return new SimpleTestResult(true, "GOST3410/ECGOST3410: Okay");
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new GOST3410Test();
        TestResult      result = test.perform();

        System.out.println(result.toString());
    }
}
