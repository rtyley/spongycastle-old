package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.IESParameters;
import org.bouncycastle.crypto.params.IESWithCipherParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

import java.math.BigInteger;

/**
 * test for ECIES - Elliptic Curve Integrated Encryption Scheme
 */
public class ECIESTest
    extends SimpleTest
{
    ECIESTest()
    {
    }

    public String getName()
    {
        return "ECIES";
    }

    public void performTest()
        throws Exception
    {
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

        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            curve.decodePoint(Hex.decode("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5")), // Q
            params);

        AsymmetricCipherKeyPair  p1 = new AsymmetricCipherKeyPair(pubKey, priKey);
        AsymmetricCipherKeyPair  p2 = new AsymmetricCipherKeyPair(pubKey, priKey);
    
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

        byte[]   out1 = i1.processBlock(message, 0, message.length);

        if (!areEqual(out1, Hex.decode("2442ae1fbf90dd9c06b0dcc3b27e69bd11c9aee4ad4cfc9e50eceb44")))
        {
            fail("stream cipher test failed on enc");
        }

        byte[]   out2 = i2.processBlock(out1, 0, out1.length);

        if (!areEqual(out2, message))
        {
            fail("stream cipher test failed");
        }

        //
        // twofish with CBC
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

        out1 = i1.processBlock(message, 0, message.length);

        if (!areEqual(out1, Hex.decode("2ea288651e21576215f2424bbb3f68816e282e3931b44bd1c429ebdb5f1b290cf1b13309")))
        {
            fail("twofish cipher test failed on enc");
        }

        out2 = i2.processBlock(out1, 0, out1.length);

        if (!areEqual(out2, message))
        {
            fail("twofish cipher test failed");
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new ECIESTest());
    }
}
