package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAValidationParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * Test based on FIPS 186-2, Appendix 5, an example of DSA.
 */
public class DSATest
    implements Test
{
    SecureRandom    random = new SecureRandom()
    {
        boolean first = true;

        public void nextBytes(byte[] bytes)
        {
            byte[] k1 = Hex.decode("d5014e4b60ef2ba8b6211b4062ba3224e0427dd3");
            byte[] k2 = Hex.decode("345e8d05c075c3a508df729a1685690e68fcfb8c8117847e89063bca1f85d968fd281540b6e13bd1af989a1fbf17e06462bf511f9d0b140fb48ac1b1baa5bded");

            if (first)
            {
                System.arraycopy(k1, 0, bytes, 0, k1.length);
                first = false;
            }
            else
            {
                System.arraycopy(k2, 0, bytes, 0, k2.length);
            }
        }
    };

    SecureRandom    keyRandom = new SecureRandom()
    {
        public void nextBytes(byte[] bytes)
        {
            byte[] k = Hex.decode("b5014e4b60ef2ba8b6211b4062ba3224e0427dd3");

            int i;

            for (i = 0; i < (bytes.length - k.length); i += k.length)
            {
                System.arraycopy(k, 0, bytes, i, k.length);
            }

            if (i > bytes.length)
            {
                System.arraycopy(k, 0, bytes, i - k.length, bytes.length - (i - k.length));
            }
            else
            {
                System.arraycopy(k, 0, bytes, i, bytes.length - i);
            }
        }
    };

    BigInteger  pValue = new BigInteger("8df2a494492276aa3d25759bb06869cbeac0d83afb8d0cf7cbb8324f0d7882e5d0762fc5b7210eafc2e9adac32ab7aac49693dfbf83724c2ec0736ee31c80291", 16);
    BigInteger  qValue = new BigInteger("c773218c737ec8ee993b4f2ded30f48edace915f", 16);

    public String getName()
    {
        return "DSA";
    }

    public TestResult perform()
    {
        BigInteger              r = new BigInteger("68076202252361894315274692543577577550894681403");
        BigInteger              s = new BigInteger("1089214853334067536215539335472893651470583479365");
        DSAParametersGenerator  pGen = new DSAParametersGenerator();

        pGen.init(512, 80, random);

        DSAParameters           params = pGen.generateParameters();
        DSAValidationParameters pValid = params.getValidationParameters();

        if (pValid.getCounter() != 105)
        {
            return new SimpleTestResult(false, getName() + ": Counter wrong");
        }

        if (!pValue.equals(params.getP()) || !qValue.equals(params.getQ()))
        {
            return new SimpleTestResult(false, getName() + ": p or q wrong");
        }

        DSAKeyPairGenerator         dsaKeyGen = new DSAKeyPairGenerator();
        DSAKeyGenerationParameters  genParam = new DSAKeyGenerationParameters(keyRandom, params);

        dsaKeyGen.init(genParam);

        AsymmetricCipherKeyPair  pair = dsaKeyGen.generateKeyPair();

        ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), keyRandom);

        DSASigner dsa = new DSASigner();

        dsa.init(true, param);

        byte[] message = new BigInteger("968236873715988614170569073515315707566766479517").toByteArray();
        BigInteger[] sig = dsa.generateSignature(message);

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

        dsa.init(false, pair.getPublic());

        if (dsa.verifySignature(message, sig[0], sig[1]))
        {
            return new SimpleTestResult(true, getName() + ": Okay");
        }
        else
        {
            return new SimpleTestResult(false, getName() + ": verification fails");
        }
    }

    public static void main(
        String[]    args)
    {
        DSATest         test = new DSATest();
        TestResult      result = test.perform();

        System.out.println(result);
    }
}
