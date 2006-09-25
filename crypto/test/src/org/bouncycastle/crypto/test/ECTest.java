package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;

/**
 * ECDSA tests are taken from X9.62.
 */
public class ECTest
    extends SimpleTest
{   
    /**
     * X9.62 - 1998,<br>
     * J.3.1, Page 152, ECDSA over the field Fp<br>
     * an example with 192 bit prime
     */
    private void testECDSA192bitPrime()
    {
        BigInteger r = new BigInteger("3342403536405981729393488334694600415596881826869351677613");
        BigInteger s = new BigInteger("5735822328888155254683894997897571951568553642892029982342");

        byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("6140507067065001063065065565667405560006161556565665656654"));

        SecureRandom    k = new FixedSecureRandom(kData);

        ECCurve.Fp curve = new ECCurve.Fp(
            new BigInteger("6277101735386680763835789423207666416083908700390324961279"), // q
            new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), // a
            new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16)); // b

        ECDomainParameters params = new ECDomainParameters(
                curve,
                curve.decodePoint(Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), // G
                new BigInteger("6277101735386680763835789423176059013767194773182842284081")); // n

        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
            new BigInteger("651056770906015076056810763456358567190100156695615665659"), // d
            params);

        ParametersWithRandom param = new ParametersWithRandom(priKey, k);

        ECDSASigner ecdsa = new ECDSASigner();

        ecdsa.init(true, param);

        byte[] message = new BigInteger("968236873715988614170569073515315707566766479517").toByteArray();
        BigInteger[] sig = ecdsa.generateSignature(message);

        if (!r.equals(sig[0]))
        {
            fail("r component wrong." + System.getProperty("line.separator")
                + " expecting: " + r + System.getProperty("line.separator")
                + " got      : " + sig[0]);
        }

        if (!s.equals(sig[1]))
        {
            fail("s component wrong." + System.getProperty("line.separator")
                + " expecting: " + s + System.getProperty("line.separator")
                + " got      : " + sig[1]);
        }

        // Verify the signature
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            curve.decodePoint(Hex.decode("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5")), // Q
            params);

        ecdsa.init(false, pubKey);
        if (!ecdsa.verifySignature(message, sig[0], sig[1]))
        {
            fail("verification fails");
        }
    }

    private void decodeTest()
    {
        ECCurve.Fp curve = new ECCurve.Fp(
                new BigInteger("6277101735386680763835789423207666416083908700390324961279"), // q
                new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), // a
                new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16)); // b
        
        ECPoint p = curve.decodePoint(Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012"));
        
        if (!p.getX().toBigInteger().equals(new BigInteger("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16)))
        {
            fail("x uncompressed incorrectly");
        }
        
        if (!p.getY().toBigInteger().equals(new BigInteger("7192b95ffc8da78631011ed6b24cdd573f977a11e794811", 16)))
        {
            fail("y uncompressed incorrectly");
        }
        
        byte[] encoding = p.getEncoded();
        
        if (!areEqual(encoding, Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")))
        {
            fail("point compressed incorrectly");
        }
    }
    
    /**
     * X9.62 - 1998,<br>
     * J.3.2, Page 155, ECDSA over the field Fp<br>
     * an example with 239 bit prime
     */
    private void testECDSA239bitPrime()
    {
        BigInteger r = new BigInteger("308636143175167811492622547300668018854959378758531778147462058306432176");
        BigInteger s = new BigInteger("323813553209797357708078776831250505931891051755007842781978505179448783");

        byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("700000017569056646655505781757157107570501575775705779575555657156756655"));

        SecureRandom    k = new FixedSecureRandom(true, kData);

        ECCurve.Fp curve = new ECCurve.Fp(
            new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
            new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
            new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

        ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
            new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307")); // n

        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
            new BigInteger("876300101507107567501066130761671078357010671067781776716671676178726717"), // d
            params);

        ECDSASigner ecdsa = new ECDSASigner();
        ParametersWithRandom param = new ParametersWithRandom(priKey, k);

        ecdsa.init(true, param);

        byte[] message = new BigInteger("968236873715988614170569073515315707566766479517").toByteArray();
        BigInteger[] sig = ecdsa.generateSignature(message);

        if (!r.equals(sig[0]))
        {
            fail("r component wrong." + System.getProperty("line.separator")
                + " expecting: " + r + System.getProperty("line.separator")
                + " got      : " + sig[0]);
        }

        if (!s.equals(sig[1]))
        {
            fail("s component wrong." + System.getProperty("line.separator")
                + " expecting: " + s + System.getProperty("line.separator")
                + " got      : " + sig[1]);
        }

        // Verify the signature
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            curve.decodePoint(Hex.decode("025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70")), // Q
            params);

        ecdsa.init(false, pubKey);
        if (!ecdsa.verifySignature(message, sig[0], sig[1]))
        {
            fail("signature fails");
        }
    }


    /**
     * X9.62 - 1998,<br>
     * J.2.1, Page 100, ECDSA over the field F2m<br>
     * an example with 191 bit binary field
     */
    private void testECDSA191bitBinary()
    {
        BigInteger r = new BigInteger("87194383164871543355722284926904419997237591535066528048");
        BigInteger s = new BigInteger("308992691965804947361541664549085895292153777025772063598");
    
        byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("1542725565216523985789236956265265265235675811949404040041"));
        
        SecureRandom    k = new FixedSecureRandom(kData);

        ECCurve.F2m curve = new ECCurve.F2m(
            191, // m
            9, //k
            new BigInteger("2866537B676752636A68F56554E12640276B649EF7526267", 16), // a
            new BigInteger("2E45EF571F00786F67B0081B9495A3D95462F5DE0AA185EC", 16)); // b
    
        ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.decodePoint(Hex.decode("0436B3DAF8A23206F9C4F299D7B21A9C369137F2C84AE1AA0D765BE73433B3F95E332932E70EA245CA2418EA0EF98018FB")), // G
            new BigInteger("1569275433846670190958947355803350458831205595451630533029"), // n
            BigInteger.valueOf(2)); // h
    
        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
            new BigInteger("1275552191113212300012030439187146164646146646466749494799"), // d
            params);
    
        ECDSASigner ecdsa = new ECDSASigner();
        ParametersWithRandom param = new ParametersWithRandom(priKey, k);
    
        ecdsa.init(true, param);
    
        byte[] message = new BigInteger("968236873715988614170569073515315707566766479517").toByteArray();
        BigInteger[] sig = ecdsa.generateSignature(message);
    
        if (!r.equals(sig[0]))
        {
            fail("r component wrong." + System.getProperty("line.separator")
                + " expecting: " + r + System.getProperty("line.separator")
                + " got      : " + sig[0]);
        }
    
        if (!s.equals(sig[1]))
        {
            fail("s component wrong." + System.getProperty("line.separator")
                + " expecting: " + s + System.getProperty("line.separator")
                + " got      : " + sig[1]);
        }
    
        // Verify the signature
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            curve.decodePoint(Hex.decode("045DE37E756BD55D72E3768CB396FFEB962614DEA4CE28A2E755C0E0E02F5FB132CAF416EF85B229BBB8E1352003125BA1")), // Q
            params);

        ecdsa.init(false, pubKey);
        if (!ecdsa.verifySignature(message, sig[0], sig[1]))
        {
            fail("signature fails");
        }
    }


    /**
     * X9.62 - 1998,<br>
     * J.2.1, Page 100, ECDSA over the field F2m<br>
     * an example with 191 bit binary field
     */
    private void testECDSA239bitBinary()
    {
        BigInteger r = new BigInteger("21596333210419611985018340039034612628818151486841789642455876922391552");
        BigInteger s = new BigInteger("197030374000731686738334997654997227052849804072198819102649413465737174");
    
        byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("171278725565216523967285789236956265265265235675811949404040041670216363"));
        
        SecureRandom    k = new FixedSecureRandom(kData);

        ECCurve.F2m curve = new ECCurve.F2m(
            239, // m
            36, //k
            new BigInteger("32010857077C5431123A46B808906756F543423E8D27877578125778AC76", 16), // a
            new BigInteger("790408F2EEDAF392B012EDEFB3392F30F4327C0CA3F31FC383C422AA8C16", 16)); // b
    
        ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.decodePoint(Hex.decode("0457927098FA932E7C0A96D3FD5B706EF7E5F5C156E16B7E7C86038552E91D61D8EE5077C33FECF6F1A16B268DE469C3C7744EA9A971649FC7A9616305")), // G
            new BigInteger("220855883097298041197912187592864814557886993776713230936715041207411783"), // n
            BigInteger.valueOf(4)); // h
    
        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
            new BigInteger("145642755521911534651321230007534120304391871461646461466464667494947990"), // d
            params);
    
        ECDSASigner ecdsa = new ECDSASigner();
        ParametersWithRandom param = new ParametersWithRandom(priKey, k);
    
        ecdsa.init(true, param);
    
        byte[] message = new BigInteger("968236873715988614170569073515315707566766479517").toByteArray();
        BigInteger[] sig = ecdsa.generateSignature(message);
    
        if (!r.equals(sig[0]))
        {
            fail("r component wrong." + System.getProperty("line.separator")
                + " expecting: " + r + System.getProperty("line.separator")
                + " got      : " + sig[0]);
        }
    
        if (!s.equals(sig[1]))
        {
            fail("s component wrong." + System.getProperty("line.separator")
                + " expecting: " + s + System.getProperty("line.separator")
                + " got      : " + sig[1]);
        }
    
        // Verify the signature
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            curve.decodePoint(Hex.decode("045894609CCECF9A92533F630DE713A958E96C97CCB8F5ABB5A688A238DEED6DC2D9D0C94EBFB7D526BA6A61764175B99CB6011E2047F9F067293F57F5")), // Q
            params);

        ecdsa.init(false, pubKey);
        if (!ecdsa.verifySignature(message, sig[0], sig[1]))
        {
            fail("signature fails");
        }
    }

    /**
     * General test for long digest.
     */
    private void testECDSA239bitBinaryAndLargeDigest()
    {
        BigInteger r = new BigInteger("21596333210419611985018340039034612628818151486841789642455876922391552");
        BigInteger s = new BigInteger("87626799441093658509023277770579403014298417038607966989658087651831660");
    
        byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("171278725565216523967285789236956265265265235675811949404040041670216363"));
        
        SecureRandom    k = new FixedSecureRandom(kData);

        ECCurve.F2m curve = new ECCurve.F2m(
            239, // m
            36, //k
            new BigInteger("32010857077C5431123A46B808906756F543423E8D27877578125778AC76", 16), // a
            new BigInteger("790408F2EEDAF392B012EDEFB3392F30F4327C0CA3F31FC383C422AA8C16", 16)); // b
    
        ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.decodePoint(Hex.decode("0457927098FA932E7C0A96D3FD5B706EF7E5F5C156E16B7E7C86038552E91D61D8EE5077C33FECF6F1A16B268DE469C3C7744EA9A971649FC7A9616305")), // G
            new BigInteger("220855883097298041197912187592864814557886993776713230936715041207411783"), // n
            BigInteger.valueOf(4)); // h
    
        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
            new BigInteger("145642755521911534651321230007534120304391871461646461466464667494947990"), // d
            params);
    
        ECDSASigner ecdsa = new ECDSASigner();
        ParametersWithRandom param = new ParametersWithRandom(priKey, k);
    
        ecdsa.init(true, param);
    
        byte[] message = new BigInteger("968236873715988614170569073515315707566766479517968236873715988614170569073515315707566766479517968236873715988614170569073515315707566766479517").toByteArray();
        BigInteger[] sig = ecdsa.generateSignature(message);
    
        if (!r.equals(sig[0]))
        {
            fail("r component wrong." + System.getProperty("line.separator")
                + " expecting: " + r + System.getProperty("line.separator")
                + " got      : " + sig[0]);
        }
    
        if (!s.equals(sig[1]))
        {
            fail("s component wrong." + System.getProperty("line.separator")
                + " expecting: " + s + System.getProperty("line.separator")
                + " got      : " + sig[1]);
        }
    
        // Verify the signature
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            curve.decodePoint(Hex.decode("045894609CCECF9A92533F630DE713A958E96C97CCB8F5ABB5A688A238DEED6DC2D9D0C94EBFB7D526BA6A61764175B99CB6011E2047F9F067293F57F5")), // Q
            params);

        ecdsa.init(false, pubKey);
        if (!ecdsa.verifySignature(message, sig[0], sig[1]))
        {
            fail("signature fails");
        }
    }

    /**
     * key generation test
     */
    private void testECDSAKeyGenTest()
    {
        SecureRandom    random = new SecureRandom();
        ECCurve.Fp curve = new ECCurve.Fp(
            new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
            new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
            new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

        ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
            new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307")); // n


        ECKeyPairGenerator          pGen = new ECKeyPairGenerator();
        ECKeyGenerationParameters   genParam = new ECKeyGenerationParameters(
                                        params,
                                        random);

        pGen.init(genParam);

        AsymmetricCipherKeyPair  pair = pGen.generateKeyPair();
    
        ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), random);

        ECDSASigner ecdsa = new ECDSASigner();

        ecdsa.init(true, param);

        byte[] message = new BigInteger("968236873715988614170569073515315707566766479517").toByteArray();
        BigInteger[] sig = ecdsa.generateSignature(message);

        ecdsa.init(false, pair.getPublic());

        if (!ecdsa.verifySignature(message, sig[0], sig[1]))
        {
            fail("signature fails");
        }
    }

    /**
     * Basic Key Agreement Test
     */
    private void testECBasicAgreementTest()
    {
        SecureRandom    random = new SecureRandom();
        ECCurve.Fp curve = new ECCurve.Fp(
            new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
            new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
            new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

        ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
            new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307")); // n


        ECKeyPairGenerator          pGen = new ECKeyPairGenerator();
        ECKeyGenerationParameters   genParam = new ECKeyGenerationParameters(
                                        params,
                                        random);

        pGen.init(genParam);

        AsymmetricCipherKeyPair  p1 = pGen.generateKeyPair();
        AsymmetricCipherKeyPair  p2 = pGen.generateKeyPair();
    
        //
        // two way
        //
        BasicAgreement    e1 = new ECDHBasicAgreement();
        BasicAgreement    e2 = new ECDHBasicAgreement();

        e1.init(p1.getPrivate());
        e2.init(p2.getPrivate());

        BigInteger   k1 = e1.calculateAgreement(p2.getPublic());
        BigInteger   k2 = e2.calculateAgreement(p1.getPublic());

        if (!k1.equals(k2))
        {
            fail("calculated agreement test failed");
        }

        //
        // two way
        //
        e1 = new ECDHCBasicAgreement();
        e2 = new ECDHCBasicAgreement();

        e1.init(p1.getPrivate());
        e2.init(p2.getPrivate());

        k1 = e1.calculateAgreement(p2.getPublic());
        k2 = e2.calculateAgreement(p1.getPublic());

        if (!k1.equals(k2))
        {
            fail("calculated agreement test failed");
        }
    }



    public String getName()
    {
        return "EC";
    }

    public void performTest()
    {
        decodeTest();
        testECDSA192bitPrime();
        testECDSA239bitPrime();
        testECDSA191bitBinary();
        testECDSA239bitBinary();
        testECDSAKeyGenTest();
        testECBasicAgreementTest();
        testECDSA239bitBinaryAndLargeDigest();
    }


    public static void main(
        String[]    args)
    {
        runTest(new ECTest());
    }
}

