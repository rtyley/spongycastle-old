package org.spongycastle.math.ec;

import java.math.BigInteger;

public class ECCurveFp extends ECCurve
{
    public ECCurveFp(BigInteger q, BigInteger a, BigInteger b)
    {
        super(q, a, b);
    }

    public ECFieldElement fromBigInteger(BigInteger x)
    {
        return new ECFieldElementFp(this.getQ(), x);
    }

    public BigInteger getQ()
    {
        return q;
    }

    // 4.2.1 pg 17
    public ECPoint decodePoint(byte[] encoded)
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

            ECFieldElement x = new ECFieldElementFp(this.q, new BigInteger(1, i));
            ECFieldElement alpha = x.multiply(x.square()).add(x.multiply(a).add(b));
            ECFieldElement beta = alpha.sqrt();
            if ( beta == null )
            {
                throw new RuntimeException("Invalid point compression");
            }

            int bit0 = (beta.toBigInteger().testBit(0) ? 0 : 1);

            if ( bit0 == ytilde )
            {
                p = new ECPointFp(this, x, beta);
            }
            else
            {
                p = new ECPointFp(this, x,
                    new ECFieldElementFp(this.q, q.subtract(beta.toBigInteger())));
            }
            break;
        case 0x04:
            byte[]  xEnc = new byte[(encoded.length - 1) / 2];
            byte[]  yEnc = new byte[(encoded.length - 1) / 2];

            System.arraycopy(encoded, 1, xEnc, 0, xEnc.length);
            System.arraycopy(encoded, xEnc.length + 1, yEnc, 0, yEnc.length);

            p = new ECPointFp(this,
                    new ECFieldElementFp(this.q, new BigInteger(1, xEnc)),
                    new ECFieldElementFp(this.q, new BigInteger(1, yEnc)));
            break;
        default:
            throw new RuntimeException("Invalid point encoding 0x" + Integer.toString(encoded[0], 16));
        }

        return p;
    }
}
