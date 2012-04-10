package org.bouncycastle.math.ec;

import java.math.BigInteger;

public class ECPointFp extends ECPoint
{
    public ECPointFp(ECCurve curve, ECFieldElement x, ECFieldElement y)
    {
        super(curve, x, y);
    }

    /**
     * return the field element encoded with point compression. (S 4.3.6)
     */
    public byte[] getEncoded()
    {
        byte    PC;

        if (this.getY().toBigInteger().testBit(0))
        {
            PC = 0x02;
        }
        else
        {
            PC = 0x03;
        }

        byte[]  X = this.getX().toBigInteger().toByteArray();
        byte[]  PO = new byte[X.length + 1];

        PO[0] = PC;
        System.arraycopy(X, 0, PO, 1, X.length);

        return PO;
    }

    // B.3 pg 62
    public ECPoint add(ECPoint b)
    {
        ECFieldElement gamma = b.y.subtract(y).divide(b.x.subtract(x));

        ECFieldElement x3 = gamma.multiply(gamma).subtract(x).subtract(b.x);
        ECFieldElement y3 = gamma.multiply(x.subtract(x3)).subtract(y);

        return new ECPointFp(curve, x3, y3);
    }

    // B.3 pg 62
    public ECPoint twice()
    {
        ECFieldElement TWO = curve.fromBigInteger(BigInteger.valueOf(2));
        ECFieldElement THREE = curve.fromBigInteger(BigInteger.valueOf(3));
        ECFieldElement gamma = x.multiply(x).multiply(THREE).add(curve.a).divide(y.multiply(TWO));

        ECFieldElement x3 = gamma.multiply(gamma).subtract(x.multiply(TWO));
        ECFieldElement y3 = gamma.multiply(x.subtract(x3)).subtract(y);
            
        return new ECPointFp(curve, x3, y3);
    }

    // D.3.2 pg 102 (see Note:)
    public ECPoint subtract(ECPoint p2)
    {
        return add(new ECPointFp(curve, p2.x, p2.y.negate()));
    }

    // D.3.2 pg 101
    public ECPoint multiply(BigInteger k)
    {
        // BigInteger e = k.mod(n); // n == order this
        BigInteger e = k;

        BigInteger h = e.multiply(BigInteger.valueOf(3));

        ECPoint R = this;

        for (int i = h.bitLength() - 2; i > 0; i--)
        {             
            R = R.twice();       

            if ( h.testBit(i) && !e.testBit(i) )
            {                    
                //System.out.print("+");
                R = R.add(this);
            }
            else if ( !h.testBit(i) && e.testBit(i) )
            {
                //System.out.print("-");
                R = R.subtract(this);
            }
            // else
            // System.out.print(".");
        }
        // System.out.println();

        return R;
    }
}
