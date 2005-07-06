package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.DHAgreement;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.generators.DHBasicKeyPairGenerator;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class DHTest
    implements Test
{
    private BigInteger g512 = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
    private BigInteger p512 = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

    public String getName()
    {
        return "DH";
    }

    private TestResult testGP(
        int         size,
        BigInteger  g,
        BigInteger  p)
    {
        DHParameters                dhParams = new DHParameters(p, g);

        DHKeyGenerationParameters   params = new DHKeyGenerationParameters(new SecureRandom(), dhParams);

        DHKeyPairGenerator          kpGen = new DHKeyPairGenerator();

        kpGen.init(params);

        //
        // generate first pair
        //
        AsymmetricCipherKeyPair     pair = kpGen.generateKeyPair();

        DHPublicKeyParameters       pu1 = (DHPublicKeyParameters)pair.getPublic();
        DHPrivateKeyParameters      pv1 = (DHPrivateKeyParameters)pair.getPrivate();
        //
        // generate second pair
        //
        pair = kpGen.generateKeyPair();

        DHPublicKeyParameters       pu2 = (DHPublicKeyParameters)pair.getPublic();
        DHPrivateKeyParameters      pv2 = (DHPrivateKeyParameters)pair.getPrivate();

        //
        // two way
        //
        DHAgreement    e1 = new DHAgreement();
        DHAgreement    e2 = new DHAgreement();

        e1.init(pv1);
        e2.init(pv2);

        BigInteger  m1 = e1.calculateMessage();
        BigInteger  m2 = e2.calculateMessage();

        BigInteger   k1 = e1.calculateAgreement(pu2, m2);
        BigInteger   k2 = e2.calculateAgreement(pu1, m1);

        if (!k1.equals(k2))
        {
            return new SimpleTestResult(false, size + " bit 2-way test failed");
        }

        return new SimpleTestResult(true, this.getName() + ": Okay");
    }

    private TestResult testSimple(
        int         size,
        BigInteger  g,
        BigInteger  p)
    {
        DHParameters                dhParams = new DHParameters(p, g);

        DHKeyGenerationParameters   params = new DHKeyGenerationParameters(new SecureRandom(), dhParams);

        DHBasicKeyPairGenerator     kpGen = new DHBasicKeyPairGenerator();

        kpGen.init(params);

        //
        // generate first pair
        //
        AsymmetricCipherKeyPair     pair = kpGen.generateKeyPair();

        DHPublicKeyParameters       pu1 = (DHPublicKeyParameters)pair.getPublic();
        DHPrivateKeyParameters      pv1 = (DHPrivateKeyParameters)pair.getPrivate();
        //
        // generate second pair
        //
        pair = kpGen.generateKeyPair();

        DHPublicKeyParameters       pu2 = (DHPublicKeyParameters)pair.getPublic();
        DHPrivateKeyParameters      pv2 = (DHPrivateKeyParameters)pair.getPrivate();

        //
        // two way
        //
        DHBasicAgreement    e1 = new DHBasicAgreement();
        DHBasicAgreement    e2 = new DHBasicAgreement();

        e1.init(pv1);
        e2.init(pv2);

        BigInteger   k1 = e1.calculateAgreement(pu2);
        BigInteger   k2 = e2.calculateAgreement(pu1);

        if (!k1.equals(k2))
        {
            return new SimpleTestResult(false, "basic " + size + " bit 2-way test failed");
        }

        return new SimpleTestResult(true, this.getName() + ": Okay");
    }

    public TestResult perform()
    {
        TestResult      result = testSimple(512, g512, p512);

        if (!result.isSuccessful())
        {
            return result;
        }
        
        result = testGP(512, g512, p512);
        if (!result.isSuccessful())
        {
            return result;
        }
        
        return result;
    }

    public static void main(
        String[]    args)
    {
        DHTest         test = new DHTest();
        TestResult      result = test.perform();

        System.out.println(result);
    }
}
