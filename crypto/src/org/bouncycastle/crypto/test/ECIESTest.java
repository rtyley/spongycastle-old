package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.IESParameters;
import org.bouncycastle.crypto.params.IESWithCipherParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * test for ECIES - Elliptic Curve Integrated Encryption Scheme
 */
public class ECIESTest
    implements Test
{
    ECIESTest()
    {
    }

    public String getName()
    {
        return "ECIES";
    }

    private boolean sameAs(
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
        // stream test
        //
        IESEngine      i1 = new IESEngine(
                                   new ECDHBasicAgreement(),
                                   new KDF2BytesGenerator(new SHA1Digest()),
                                   new HMac(new SHA1Digest()));
        IESEngine      i2 = new IESEngine(
                                   new ECDHBasicAgreement(),
                                   new KDF2BytesGenerator(new SHA1Digest()),
                                   new HMac(new SHA1Digest()));
        byte[]         d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        byte[]         e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };
        IESParameters  p = new IESParameters(d, e, 64);

        i1.init(true, p1.getPrivate(), p2.getPublic(), p);
        i2.init(false, p2.getPrivate(), p1.getPublic(), p);

        byte[] message = Hex.decode("1234567890abcdef");

        try
        {
            byte[]   out1 = i1.processBlock(message, 0, message.length);

            byte[]   out2 = i2.processBlock(out1, 0, out1.length);

            if (!sameAs(out2, message))
            {
                return new SimpleTestResult(false, this.getName() + ": stream cipher test failed");
            }
      
        }
        catch (Exception ex)
        {
            return new SimpleTestResult(false, this.getName() + ": stream cipher test exception " + ex.toString());
        }

        //
        // twofish with IV0 test
        //
        BufferedBlockCipher c1 = new PaddedBufferedBlockCipher(
                                    new CBCBlockCipher(new TwofishEngine()));
        BufferedBlockCipher c2 = new PaddedBufferedBlockCipher(
                                    new CBCBlockCipher(new TwofishEngine()));
        i1 = new IESEngine(
                       new ECDHBasicAgreement(),
                       new KDF2BytesGenerator(new SHA1Digest()),
                       new HMac(new SHA1Digest()),
                       c1);
        i2 = new IESEngine(
                       new ECDHBasicAgreement(),
                       new KDF2BytesGenerator(new SHA1Digest()),
                       new HMac(new SHA1Digest()),
                       c2);
        d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };
        p = new IESWithCipherParameters(d, e, 64, 128);

        i1.init(true, p1.getPrivate(), p2.getPublic(), p);
        i2.init(false, p2.getPrivate(), p1.getPublic(), p);

        message = Hex.decode("1234567890abcdef");

        try
        {
            byte[]    out1 = i1.processBlock(message, 0, message.length);

            byte[]    out2 = i2.processBlock(out1, 0, out1.length);

            if (!sameAs(out2, message))
            {
                return new SimpleTestResult(false, this.getName() + ": twofish cipher test failed");
            }
        }
        catch (Exception ex)
        {
            return new SimpleTestResult(false, this.getName() + ": twofish cipher test exception " + ex.toString());
        }

        return new SimpleTestResult(true, this.getName() + ": Okay");
    }

    public static void main(
        String[]    args)
    {
        ECIESTest    test = new ECIESTest();
        TestResult      result = test.perform();

        System.out.println(result);
    }
}
