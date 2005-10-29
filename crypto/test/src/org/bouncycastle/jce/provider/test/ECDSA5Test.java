package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;

import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class ECDSA5Test
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
    private class ECDSA239bitPrime
        implements Test
    {
        BigInteger r = new BigInteger("308636143175167811492622547300668018854959378758531778147462058306432176");
        BigInteger s = new BigInteger("323813553209797357708078776831250505931891051755007842781978505179448783");

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
            return "ECDSA5 239 bit prime";
        }

        public TestResult perform()
        {
            try
            {
                EllipticCurve curve = new EllipticCurve(
                    new ECFieldFp(new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839")), // q
                    new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
                    new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

                ECParameterSpec spec = new ECParameterSpec(
                    curve,
                    ECPointUtil.decodePoint(curve, Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
                    new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"), // n
                    1); // h
                

                ECPrivateKeySpec priKey = new ECPrivateKeySpec(
                    new BigInteger("876300101507107567501066130761671078357010671067781776716671676178726717"), // d
                    spec);

                ECPublicKeySpec pubKey = new ECPublicKeySpec(
                    ECPointUtil.decodePoint(curve, Hex.decode("025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70")), // Q
                    spec);

                Signature           sgr = Signature.getInstance("ECDSA", "BC");
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

    private class GenerationTest
        implements Test
    {
        public String getName()
        {
            return "EC/ECDSA Generation";
        }

        public TestResult perform()
        {
            try
            {
                //
                // ECDSA generation test
                //
                byte[]              data = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
                Signature s = Signature.getInstance("ECDSA", "BC");
                KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");

                EllipticCurve curve = new EllipticCurve(
                    new ECFieldFp(new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839")), // q
                    new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
                    new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

                ECParameterSpec ecSpec = new ECParameterSpec(
                    curve,
                    ECPointUtil.decodePoint(curve, Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
                    new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"), // n
                    1); // h

                g.initialize(ecSpec, new SecureRandom());

                KeyPair p = g.generateKeyPair();

                PrivateKey sKey = p.getPrivate();
                PublicKey  vKey = p.getPublic();

                s.initSign(sKey);

                s.update(data);

                byte[] sigBytes = s.sign();

                s = Signature.getInstance("ECDSA", "BC");

                s.initVerify(vKey);

                s.update(data);

                if (!s.verify(sigBytes))
                {
                    return new SimpleTestResult(false, this.getName() + ": ECDSA verification failed");
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
        new ECDSA239bitPrime(),
        new GenerationTest()
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
        return "ECDSA5";
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

        return new SimpleTestResult(true, "ECDSA5: Okay");
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

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new ECDSA5Test();
        TestResult      result = test.perform();

        System.out.println(result.toString());
    }
}
