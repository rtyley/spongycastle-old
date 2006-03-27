package org.bouncycastle.math.ec.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class PointCompressionTest
    extends TestCase
{
    public static final int NUM_ROUNDS = 1;
    public static final String CURVE = "sect163r2";
    public static final String[] CURVES = {"sect163r2", "sect233r1",
        "sect283r1", "sect409r1", "sect571r1"};
    
    public void testCompression()
    {
        SecureRandom secRand = new SecureRandom();

        for (int i = 0; i < NUM_ROUNDS; i++)
        {
            for (int j = 0; j < CURVES.length; j++)
            {
                X9ECParameters x9ECParameters
                    = SECNamedCurves.getByName(CURVES[j]);

                BigInteger n = x9ECParameters.getN();
                BigInteger k = new BigInteger(n.bitLength() - 1, secRand);
//                System.out.println("k = " + k);

                ECCurve curve = x9ECParameters.getCurve();
                ECPoint g = x9ECParameters.getG();
                ECPoint.F2m q = (ECPoint.F2m)g.multiply(k);

                // Enforce point compression
                ECPoint.F2m q1
                    = new ECPoint.F2m(curve, q.getX(), q.getY(), true); 

                // No Point compression
//                ECPoint.F2m q1 = q;

                byte[] compressedBarr = q1.getEncoded();

//                System.out.println("compressedBarr = " + new String(Hex.encode(compressedBarr)));

                ECPoint q2 = curve.decodePoint(compressedBarr);

                assertEquals(CURVES[j] + ": q1 does not equal q2", q1, q2);
            }
        }
    }
    
    public static Test suite()
    {
        return new TestSuite(PointCompressionTest.class);
    }
}
