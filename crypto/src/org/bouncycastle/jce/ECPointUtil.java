package org.bouncycastle.jce;

import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import org.bouncycastle.math.ec.ECFieldElement;

/**
 * Utility class for handling EC point compression.
 */
public class ECPointUtil
{
    /**
     * decode a point on this curve which has been encoded using
     * point compression (X9.62 s 4.2.1 pg 17) returning the point.
     */
    public static ECPoint decodePoint(
        EllipticCurve   curve,
        byte[]          encoded)
    {
        ECPoint p = null;

        switch (encoded[0])
        {
            // compressed
        case 0x02:
        case 0x03:
            int ytilde = encoded[0] & 1;
            byte[]  i = new byte[encoded.length - 1];

            System.arraycopy(encoded, 1, i, 0, i.length);

            BigInteger     q = ((ECFieldFp)curve.getField()).getP();
            ECFieldElement x = new ECFieldElement.Fp(q, new BigInteger(1, i));
            ECFieldElement a = new ECFieldElement.Fp(q, curve.getA());
            ECFieldElement b = new ECFieldElement.Fp(q, curve.getB());
            ECFieldElement alpha = x.multiply(x.square()).add(x.multiply(a).add(b));

            BigInteger     beta = alpha.sqrt().toBigInteger();

            //
            // if we can't find a sqrt we haven't got a point on the
            // curve - run!
            //
            if (beta == null)
            {
                throw new RuntimeException("Invalid point compression");
            }

            int bit0 = beta.testBit(0) ? 1 : 0;

            if (bit0 == ytilde)
            {
                p = new ECPoint(x.toBigInteger(), beta);
            }
            else
            {
                p = new ECPoint(x.toBigInteger(), q.subtract(beta));
            }
            break;
        case 0x04:
            byte[]  xEnc = new byte[(encoded.length - 1) / 2];
            byte[]  yEnc = new byte[(encoded.length - 1) / 2];

            System.arraycopy(encoded, 1, xEnc, 0, xEnc.length);
            System.arraycopy(encoded, xEnc.length + 1, yEnc, 0, yEnc.length);

            p = new ECPoint(new BigInteger(1, xEnc), new BigInteger(1, yEnc));
            break;
        default:
            throw new RuntimeException("Invalid point encoding 0x" + Integer.toString(encoded[0], 16));
        }

        return p;
    }
}
