package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECCurveFp;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

class k1 extends SecureRandom
{
    public void nextBytes(byte[] bytes)
    {
        byte[] k = new BigInteger("6140507067065001063065065565667405560006161556565665656654").toByteArray();

        System.arraycopy(k, k.length-bytes.length, bytes, 0, bytes.length);
    }
}

/**
 * X9.62 - 1998,<br>
 * J.3.1, Page 152, ECDSA over the field Fp<br>
 * an example with 192 bit prime
 */
class ECDSA192bitPrime
    implements Test
{
    BigInteger r = new BigInteger("3342403536405981729393488334694600415596881826869351677613");
    BigInteger s = new BigInteger("5735822328888155254683894997897571951568553642892029982342");

    SecureRandom    k = new k1();

    public String getName()
    {
        return "ECDSA 192 bit prime";
    }

    public TestResult perform()
    {
        ECCurveFp curve = new ECCurveFp(
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

        // Verify the signature
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            curve.decodePoint(Hex.decode("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5")), // Q
            params);

        ecdsa.init(false, pubKey);
        if (ecdsa.verifySignature(message, sig[0], sig[1]))
        {
            return new SimpleTestResult(true, getName() + ": Okay");
        }
        else
        {
            return new SimpleTestResult(false, getName() + ": verification fails");
        }
    }
}

/**
 * key generation test
 */
class ECDSAKeyGenTest
    implements Test
{
    public String getName()
    {
        return "ECDSA key generation test";
    }

    public TestResult perform()
    {
        SecureRandom    random = new SecureRandom();
        ECCurveFp curve = new ECCurveFp(
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

        if (ecdsa.verifySignature(message, sig[0], sig[1]))
        {
            return new SimpleTestResult(true, getName() + ": Okay");
        }
        else
        {
            return new SimpleTestResult(false, getName() + ": signature fails");
        }
    }
}

/**
 * Basic Key Agreement Test
 */
class ECBasicAgreementTest
    implements Test
{
    public String getName()
    {
        return "ECDSA basic agreement test";
    }

    public TestResult perform()
    {
        SecureRandom    random = new SecureRandom();
        ECCurveFp curve = new ECCurveFp(
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
            return new SimpleTestResult(false, this.getName() + ": calculated agreement test failed");
        }

        return new SimpleTestResult(true, this.getName() + ": Okay");
    }
}

/**
 * ECDSA tests are taken from X9.62.
 */
public class ECTest
    implements Test
{

    Test tests[] =
    {
        new ECDSA192bitPrime(),
        new ECDSAKeyGenTest(),
        new ECBasicAgreementTest()
    };

    public String getName()
    {
        return "EC";
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

        return new SimpleTestResult(true, "EC: Okay");
    }

    public static void main(
        String[]    args)
    {
        ECTest          test = new ECTest();
        TestResult      result = test.perform();

        System.out.println(result);
    }
}
