package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class ECNRTest
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

    /**
     * X9.62 - 1998,<br>
     * J.3.2, Page 155, ECDSA over the field Fp<br>
     * an example with 239 bit prime
     */
    private class ECNR239bitPrime
        implements Test
    {
        BigInteger r = new BigInteger("308636143175167811492623515537541734843573549327605293463169625072911693");
        BigInteger s = new BigInteger("852401710738814635664888632022555967400445256405412579597015412971797143");

        SecureRandom    k = new SecureRandom()
        {
            public void nextBytes(byte[] bytes)
            {
                byte[] k = new BigInteger("700000017569056646655505781757157107570501575775705779575555657156756655").toByteArray();

                System.arraycopy(k, k.length-bytes.length, bytes, 0, bytes.length);
            }
        };

        public String getName()
        {
            return "ECNR 239 bit prime";
        }

        public TestResult perform()
        {
            try
            {
                ECCurve curve = new ECCurve.Fp(
                    new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
                    new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
                    new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

                ECParameterSpec spec = new ECParameterSpec(
                    curve,
                    curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
                    new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307")); // n
                

                ECPrivateKeySpec priKey = new ECPrivateKeySpec(
                    new BigInteger("876300101507107567501066130761671078357010671067781776716671676178726717"), // d
                    spec);

                ECPublicKeySpec pubKey = new ECPublicKeySpec(
                    curve.decodePoint(Hex.decode("025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70")), // Q
                    spec);

                Signature           sgr = Signature.getInstance("SHA1withECNR", "BC");
                KeyFactory          f = KeyFactory.getInstance("ECDSA", "BC");
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
                    return new SimpleTestResult(false, this.getName() + ": 239 Bit EC verification failed");
                }

                BigInteger[]  sig = derDecode(sigBytes);

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
                return new SimpleTestResult(false, this.getName() + ": exception - " + e.toString());
            }

            return new SimpleTestResult(true, this.getName() + ": Okay");
        }
    }

 
    Test tests[] =
    {
        new ECNR239bitPrime()
    };

    protected BigInteger[] derDecode(
        byte[]  encoding)
        throws IOException
    {
        ByteArrayInputStream    bIn = new ByteArrayInputStream(encoding);
        ASN1InputStream         aIn = new ASN1InputStream(bIn);
        ASN1Sequence            s = (ASN1Sequence)aIn.readObject();

        BigInteger[]            sig = new BigInteger[2];

        sig[0] = ((DERInteger)s.getObjectAt(0)).getValue();
        sig[1] = ((DERInteger)s.getObjectAt(1)).getValue();

        return sig;
    }

    public String getName()
    {
        return "ECNR";
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

        return new SimpleTestResult(true, "ECNR: Okay");
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new ECNRTest();
        TestResult      result = test.perform();

        System.out.println(result.toString());
    }
}
