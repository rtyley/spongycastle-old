package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class SigTest
    implements Test
{
    private boolean isEqualTo(
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

    public TestResult perform()
    {
        try
        {
            Signature           sig = Signature.getInstance("SHA1WithRSAEncryption", "BC");
            KeyPairGenerator    fact;
            KeyPair             keyPair;
            byte[]              data = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };

            fact = KeyPairGenerator.getInstance("RSA", "BC");

            fact.initialize(768, new SecureRandom());

            keyPair = fact.generateKeyPair();

            PrivateKey  signingKey = keyPair.getPrivate();
            PublicKey   verifyKey = keyPair.getPublic();

            sig.initSign(signingKey);

            sig.update(data);

            byte[]  sigBytes = sig.sign();

            sig.initVerify(verifyKey);

            sig.update(data);

            if (!sig.verify(sigBytes))
            {
                return new SimpleTestResult(false, "SHA1 verification failed");
            }

            sig = Signature.getInstance("MD2WithRSAEncryption", "BC");

            sig.initSign(signingKey);

            sig.update(data);

            sigBytes = sig.sign();

            sig.initVerify(verifyKey);

            sig.update(data);

            if (!sig.verify(sigBytes))
            {
                return new SimpleTestResult(false, "MD2 verification failed");
            }

            sig = Signature.getInstance("MD5WithRSAEncryption", "BC");

            sig.initSign(signingKey);

            sig.update(data);

            sigBytes = sig.sign();

            sig.initVerify(verifyKey);

            sig.update(data);

            if (!sig.verify(sigBytes))
            {
                return new SimpleTestResult(false, "MD5 verification failed");
            }

            sig = Signature.getInstance("RIPEMD160WithRSAEncryption", "BC");

            sig.initSign(signingKey);

            sig.update(data);

            sigBytes = sig.sign();

            sig.initVerify(verifyKey);

            sig.update(data);

            if (!sig.verify(sigBytes))
            {
                return new SimpleTestResult(false, "RIPEMD160 verification failed");
            }

            //
            // RIPEMD-128
            //
            sig = Signature.getInstance("RIPEMD128WithRSAEncryption", "BC");

            sig.initSign(signingKey);

            sig.update(data);

            sigBytes = sig.sign();

            sig.initVerify(verifyKey);

            sig.update(data);

            if (!sig.verify(sigBytes))
            {
                return new SimpleTestResult(false, "RIPEMD128 verification failed");
            }

            //
            // RIPEMD256
            //
            sig = Signature.getInstance("RIPEMD256WithRSAEncryption", "BC");

            sig.initSign(signingKey);

            sig.update(data);

            sigBytes = sig.sign();

            sig.initVerify(verifyKey);

            sig.update(data);

            if (!sig.verify(sigBytes))
            {
                return new SimpleTestResult(false, "RIPEMD256 verification failed");
            }

            //
            // SHA-224
            //
            sig = Signature.getInstance("SHA224WithRSAEncryption", "BC");

            sig.initSign(signingKey);

            sig.update(data);

            sigBytes = sig.sign();

            sig.initVerify(verifyKey);

            sig.update(data);

            if (!sig.verify(sigBytes))
            {
                return new SimpleTestResult(false, "SHA224 verification failed");
            }
            
            //
            // SHA-256
            //
            sig = Signature.getInstance("SHA256WithRSAEncryption", "BC");

            sig.initSign(signingKey);

            sig.update(data);

            sigBytes = sig.sign();

            sig.initVerify(verifyKey);

            sig.update(data);

            if (!sig.verify(sigBytes))
            {
                return new SimpleTestResult(false, "SHA256 verification failed");
            }
            
            //
            // SHA-384
            //
            sig = Signature.getInstance("SHA384WithRSAEncryption", "BC");

            sig.initSign(signingKey);

            sig.update(data);

            sigBytes = sig.sign();

            sig.initVerify(verifyKey);

            sig.update(data);

            if (!sig.verify(sigBytes))
            {
                return new SimpleTestResult(false, "SHA384 verification failed");
            }
            
            //
            // SHA-512
            //
            sig = Signature.getInstance("SHA512WithRSAEncryption", "BC");

            sig.initSign(signingKey);

            sig.update(data);

            sigBytes = sig.sign();

            sig.initVerify(verifyKey);

            sig.update(data);

            if (!sig.verify(sigBytes))
            {
                return new SimpleTestResult(false, "SHA512 verification failed");
            }

            //
            // ISO Sigs.
            //
            sig = Signature.getInstance("MD5WithRSA/ISO9796-2", "BC");

            sig.initSign(signingKey);

            sig.update(data);

            sigBytes = sig.sign();

            sig.initVerify(verifyKey);

            sig.update(data);

            if (!sig.verify(sigBytes))
            {
                return new SimpleTestResult(false, "MD5/ISO verification failed");
            }

            sig = Signature.getInstance("SHA1WithRSA/ISO9796-2", "BC");

            sig.initSign(signingKey);

            sig.update(data);

            sigBytes = sig.sign();

            sig.initVerify(verifyKey);

            sig.update(data);

            if (!sig.verify(sigBytes))
            {
                return new SimpleTestResult(false, "SHA1/ISO verification failed");
            }

            sig = Signature.getInstance("RIPEMD160WithRSA/ISO9796-2", "BC");

            sig.initSign(signingKey);

            sig.update(data);

            sigBytes = sig.sign();

            sig.initVerify(verifyKey);

            sig.update(data);

            if (!sig.verify(sigBytes))
            {
                return new SimpleTestResult(false, "RIPEMD160/ISO verification failed");
            }

            //
            // standard vector test - B.1.3 RIPEMD160, implicit.
            //
            BigInteger  mod = new BigInteger("ffffffff78f6c55506c59785e871211ee120b0b5dd644aa796d82413a47b24573f1be5745b5cd9950f6b389b52350d4e01e90009669a8720bf265a2865994190a661dea3c7828e2e7ca1b19651adc2d5", 16);
            BigInteger  pub = new BigInteger("03", 16);
            BigInteger  pri = new BigInteger("2aaaaaaa942920e38120ee965168302fd0301d73a4e60c7143ceb0adf0bf30b9352f50e8b9e4ceedd65343b2179005b2f099915e4b0c37e41314bb0821ad8330d23cba7f589e0f129b04c46b67dfce9d", 16);

            KeyFactory  f = KeyFactory.getInstance("RSA", "BC");

            PrivateKey  privKey = f.generatePrivate(new RSAPrivateKeySpec(mod, pri));
            PublicKey   pubKey = f.generatePublic(new RSAPublicKeySpec(mod, pub));
            byte[]      testSig = Hex.decode("5cf9a01854dbacaec83aae8efc563d74538192e95466babacd361d7c86000fe42dcb4581e48e4feb862d04698da9203b1803b262105104d510b365ee9c660857ba1c001aa57abfd1c8de92e47c275cae");

            data = Hex.decode("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");

            sig = Signature.getInstance("RIPEMD160WithRSA/ISO9796-2", "BC");

            sig.initSign(privKey);

            sig.update(data);

            sigBytes = sig.sign();

            if (!isEqualTo(testSig, sigBytes))
            {
                return new SimpleTestResult(false, "SigTest: failed ISO9796-2 generation Test");
            }

            sig.initVerify(pubKey);

            sig.update(data);

            if (!sig.verify(sigBytes))
            {
                return new SimpleTestResult(false, "RIPEMD160/ISO verification failed");
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
        return "SigTest";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new SigTest();
        TestResult      result = test.perform();

        System.out.println(result.toString());
    }
}
