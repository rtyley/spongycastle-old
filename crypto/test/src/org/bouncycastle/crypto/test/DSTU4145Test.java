package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSTU4145Signer;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;

public class DSTU4145Test
    extends SimpleTest
{
    public String getName()
    {
        return "DSTU4145";
    }

    public void performTest()
        throws Exception
    {
        SecureRandom random = new FixedSecureRandom(Hex.decode("01025e40bd97db012b7a1d79de8e12932d247f61c6"));

        byte[] hash = Hex.decode("09c9c44277910c9aaee486883a2eb95b7180166ddf73532eeb76edaef52247ff");
        for (int i = 0; i < hash.length / 2; i++)
        {
            byte tmp = hash[i];
            hash[i] = hash[hash.length - 1 - i];
            hash[hash.length - 1 - i] = tmp;
        }

        BigInteger r = new BigInteger("274ea2c0caa014a0d80a424f59ade7a93068d08a7", 16);
        BigInteger s = new BigInteger("2100d86957331832b8e8c230f5bd6a332b3615aca", 16);

        ECCurve.F2m curve = new ECCurve.F2m(163, 3, 6, 7, BigInteger.valueOf(1), new BigInteger("5FF6108462A2DC8210AB403925E638A19C1455D21", 16));
        ECPoint P = curve.createPoint(new BigInteger("72d867f93a93ac27df9ff01affe74885c8c540420", 16), new BigInteger("0224a9c3947852b97c5599d5f4ab81122adc3fd9b", 16), false);
        BigInteger n = new BigInteger("400000000000000000002BEC12BE2262D39BCF14D", 16);

        BigInteger d = new BigInteger("183f60fdf7951ff47d67193f8d073790c1c9b5a3e", 16);
        ECPoint Q = P.multiply(d).negate();

        ECDomainParameters domain = new ECDomainParameters(curve, P, n);
        CipherParameters privKey = new ParametersWithRandom(new ECPrivateKeyParameters(d, domain), random);
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(Q, domain);

        DSTU4145Signer dstuSigner = new DSTU4145Signer();
        dstuSigner.init(true, privKey);
        BigInteger[] rs = dstuSigner.generateSignature(hash);

        if (rs[0].compareTo(r) != 0)
        {
            fail("r component wrong");
        }

        if (rs[1].compareTo(s) != 0)
        {
            fail("s component wrong");
        }

        dstuSigner.init(false, pubKey);
        if (!dstuSigner.verifySignature(hash, r, s))
        {
            fail("verification fails");
        }
    }

    public static void main(String[] args)
    {
        runTest(new DSTU4145Test());
    }
}
