package org.bouncycastle.math.ec;

import java.math.BigInteger;

/**
 * base class for points on elliptic curves.
 */
public abstract class ECPoint
{
    ECCurve        curve;
    ECFieldElement x;
    ECFieldElement y;

    protected ECPoint(ECCurve curve, ECFieldElement x, ECFieldElement y)
    {
        this.curve = curve;
        this.x = x;
        this.y = y;
    }
    
    public ECCurve getCurve()
    {
        return curve;
    }
    
    public ECFieldElement getX()
    {
        return x;
    }

    public ECFieldElement getY()
    {
        return y;
    }

    public boolean equals(
        Object  other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof ECPoint))
        {
            return false;
        }

        ECPoint o = (ECPoint)other;

        return x.equals(o.x) && y.equals(o.y);
    }

    public int hashCode()
    {
        return x.hashCode() ^ y.hashCode();
    }

    public abstract byte[] getEncoded();

    public abstract ECPoint add(ECPoint b);
    public abstract ECPoint subtract(ECPoint b);
    public abstract ECPoint twice();
    public abstract ECPoint multiply(BigInteger b);

    /**
     * Elliptic curve points over Fp
     */
    public static class Fp extends ECPoint
    {
        private boolean withCompression = true;
        
        /**
         * Create a point which encodes with point compression.
         * 
         * @param curve the curve to use
         * @param x affine x co-ordinate
         * @param y affine y co-ordinate
         */
        public Fp(ECCurve curve, ECFieldElement x, ECFieldElement y)
        {
            super(curve, x, y);
        }

        /**
         * Create a point that encodes with or without point compresion.
         * 
         * @param curve the curve to use
         * @param x affine x co-ordinate
         * @param y affine y co-ordinate
         * @param withCompression if true encode with point compression
         */
        public Fp(ECCurve curve, ECFieldElement x, ECFieldElement y, boolean withCompression)
        {
            super(curve, x, y);
            
            this.withCompression = withCompression;
        }
        
        private int getQLength(
            BigInteger p)
        {
            byte[] bytes = p.toByteArray();
            
            if (bytes[0] == 0)
            {
                return bytes.length - 1;
            }
            
            return bytes.length;
        }
            
        private byte[] intToBytes(
            BigInteger s,
            int        qLength)
        {
            byte[] bytes = s.toByteArray();
            
            if (qLength < bytes.length)
            {
                byte[] tmp = new byte[qLength];

                System.arraycopy(bytes, bytes.length - tmp.length, tmp, 0, tmp.length);
                
                return tmp;
            }
            else if (qLength > bytes.length)
            {
                byte[] tmp = new byte[qLength];

                System.arraycopy(bytes, 0, tmp, tmp.length - bytes.length, bytes.length);
                
                return tmp; 
            }
            
            return bytes;
        }
        
        /**
         * return the field element encoded with point compression. (S 4.3.6)
         */
        public byte[] getEncoded()
        {
            int qLength = getQLength(this.getX().p);
            
            if (withCompression)
            {
                byte    PC;
    
                if (this.getY().toBigInteger().testBit(0))
                {
                    PC = 0x03;
                }
                else
                {
                    PC = 0x02;
                }
    
                byte[]  X = intToBytes(this.getX().toBigInteger(), qLength);
                byte[]  PO = new byte[X.length + 1];
    
                PO[0] = PC;
                System.arraycopy(X, 0, PO, 1, X.length);
    
                return PO;
            }
            else
            {
                byte[]  X = intToBytes(this.getX().toBigInteger(), qLength);
                byte[]  Y = intToBytes(this.getY().toBigInteger(), qLength);
                byte[]  PO = new byte[X.length + Y.length + 1];
                
                PO[0] = 0x04;
                System.arraycopy(X, 0, PO, 1, X.length);
                System.arraycopy(Y, 0, PO, X.length + 1, Y.length);

                return PO;
            }
        }

        // B.3 pg 62
        public ECPoint add(ECPoint b)
        {
            ECFieldElement gamma = b.y.subtract(y).divide(b.x.subtract(x));

            ECFieldElement x3 = gamma.multiply(gamma).subtract(x).subtract(b.x);
            ECFieldElement y3 = gamma.multiply(x.subtract(x3)).subtract(y);

            return new ECPoint.Fp(curve, x3, y3);
        }

        // B.3 pg 62
        public ECPoint twice()
        {
            ECFieldElement TWO = curve.fromBigInteger(BigInteger.valueOf(2));
            ECFieldElement THREE = curve.fromBigInteger(BigInteger.valueOf(3));
            ECFieldElement gamma = x.multiply(x).multiply(THREE).add(curve.a).divide(y.multiply(TWO));

            ECFieldElement x3 = gamma.multiply(gamma).subtract(x.multiply(TWO));
            ECFieldElement y3 = gamma.multiply(x.subtract(x3)).subtract(y);
                
            return new ECPoint.Fp(curve, x3, y3);
        }

        // D.3.2 pg 102 (see Note:)
        public ECPoint subtract(ECPoint p2)
        {
            return add(new ECPoint.Fp(curve, p2.x, p2.y.negate()));
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

                if (h.testBit(i) && !e.testBit(i))
                {                    
                    //System.out.print("+");
                    R = R.add(this);
                }
                else if (!h.testBit(i) && e.testBit(i))
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
    
    /**
     * Elliptic curve points over Fp
     */
    public static class F2m extends ECPoint
    {

        /**
         * @param curve
         * @param x
         * @param y
         */
        protected F2m(ECCurve curve, ECFieldElement x, ECFieldElement y)
        {
            super(curve, x, y);
        }

        /* (non-Javadoc)
         * @see org.bouncycastle.math.ec.ECPoint#getEncoded()
         */
        public byte[] getEncoded()
        {
            // TODO Auto-generated method stub
            return null;
        }

        /* (non-Javadoc)
         * @see org.bouncycastle.math.ec.ECPoint#add(org.bouncycastle.math.ec.ECPoint)
         */
        public ECPoint add(ECPoint b)
        {
            // TODO Auto-generated method stub
            return null;
        }

        /* (non-Javadoc)
         * @see org.bouncycastle.math.ec.ECPoint#subtract(org.bouncycastle.math.ec.ECPoint)
         */
        public ECPoint subtract(ECPoint b)
        {
            // TODO Auto-generated method stub
            return null;
        }

        /* (non-Javadoc)
         * @see org.bouncycastle.math.ec.ECPoint#twice()
         */
        public ECPoint twice()
        {
            // TODO Auto-generated method stub
            return null;
        }

        /* (non-Javadoc)
         * @see org.bouncycastle.math.ec.ECPoint#multiply(java.math.BigInteger)
         */
        public ECPoint multiply(BigInteger b)
        {
            // TODO Auto-generated method stub
            return null;
        }
        
    }
}
