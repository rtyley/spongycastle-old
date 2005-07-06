package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class NamedCurveTest
    implements Test
{
    private String  name;

    NamedCurveTest()
    {
        this("prime192v1");
    }

    NamedCurveTest(
        String  name)
    {
        this.name = name;
    }

    public TestResult perform()
    {
        try
        {
            ECGenParameterSpec     ecSpec = new ECGenParameterSpec(name);

            if (ecSpec == null)
            {
                return new SimpleTestResult(false, getName() + " no curve for " + name + " found.");
            }

            KeyPairGenerator    g = KeyPairGenerator.getInstance("ECDH", "BC");

            g.initialize(ecSpec, new SecureRandom());

            //
            // a side
            //
            KeyPair aKeyPair = g.generateKeyPair();

            KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDHC", "BC");

            aKeyAgree.init(aKeyPair.getPrivate());

            //
            // b side
            //
            KeyPair bKeyPair = g.generateKeyPair();

            KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDHC", "BC");

            bKeyAgree.init(bKeyPair.getPrivate());

            //
            // agreement
            //
            aKeyAgree.doPhase(bKeyPair.getPublic(), true);
            bKeyAgree.doPhase(aKeyPair.getPublic(), true);

            BigInteger  k1 = new BigInteger(aKeyAgree.generateSecret());
            BigInteger  k2 = new BigInteger(bKeyAgree.generateSecret());

            if (!k1.equals(k2))
            {
                return new SimpleTestResult(false, getName() + " 2-way test failed");
            }

            //
            // public key encoding test
            //
            byte[]              pubEnc = aKeyPair.getPublic().getEncoded();
            KeyFactory          keyFac = KeyFactory.getInstance("ECDH", "BC");
            X509EncodedKeySpec  pubX509 = new X509EncodedKeySpec(pubEnc);
            ECPublicKey         pubKey = (ECPublicKey)keyFac.generatePublic(pubX509);

            if (!pubKey.getW().equals(((ECPublicKey)aKeyPair.getPublic()).getW()))
            {
                return new SimpleTestResult(false, getName() + ": public key encoding (Q test) failed");
            }

            if (!(pubKey.getParams() instanceof ECNamedCurveSpec))
            {
                return new SimpleTestResult(false, getName() + ": public key encoding not named curve");
            }

            //
            // private key encoding test
            //
            byte[]              privEnc = aKeyPair.getPrivate().getEncoded();
            PKCS8EncodedKeySpec privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
            ECPrivateKey        privKey = (ECPrivateKey)keyFac.generatePrivate(privPKCS8);

            if (!privKey.getS().equals(((ECPrivateKey)aKeyPair.getPrivate()).getS()))
            {
                return new SimpleTestResult(false, getName() + ": private key encoding (S test) failed");
            }

            if (!(privKey.getParams() instanceof ECNamedCurveSpec))
            {
                return new SimpleTestResult(false, getName() + ": private key encoding not named curve");
            }

            if (!((ECNamedCurveSpec)privKey.getParams()).getName().equals(name))
            {
                return new SimpleTestResult(false, getName() + ": private key encoding wrong named curve");
            }

            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": exception - " + e.toString());
        }
    }

    public String getName()
    {
        return "NamedCurve";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test;

        if (args.length == 0)
        {
            test = new NamedCurveTest();
        }
        else
        {
            test = new NamedCurveTest(args[0]);
        }

        TestResult      result = test.perform();

        System.out.println(result.toString());
    }
}
