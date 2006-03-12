package org.bouncycastle.math.ec;

import java.math.BigInteger;

import org.bouncycastle.asn1.x9.X9IntegerConverter;

/**
 * base class for points on elliptic curves.
 */
public abstract class ECPoint
{
    ECCurve        curve;
    ECFieldElement x;
    ECFieldElement y;
    
    private static X9IntegerConverter converter = new X9IntegerConverter();

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

    public boolean isInfinity()
    {
        return x == null && y == null;
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
        private boolean withCompression;
        
        /**
         * Create a point which encodes with point compression.
         * 
         * @param curve the curve to use
         * @param x affine x co-ordinate
         * @param y affine y co-ordinate
         */
        public Fp(ECCurve curve, ECFieldElement x, ECFieldElement y)
        {
            this(curve, x, y, false);
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
         
        /**
         * return the field element encoded with point compression. (S 4.3.6)
         */
        public byte[] getEncoded()
        {
            int qLength = converter.getQLength(((ECFieldElement.Fp)this.getX()).q);
            
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
    
                byte[]  X = converter.integerToBytes(this.getX().toBigInteger(), qLength);
                byte[]  PO = new byte[X.length + 1];
    
                PO[0] = PC;
                System.arraycopy(X, 0, PO, 1, X.length);
    
                return PO;
            }
            else
            {
                byte[]  X = converter.integerToBytes(this.getX().toBigInteger(), qLength);
                byte[]  Y = converter.integerToBytes(this.getY().toBigInteger(), qLength);
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
     * Elliptic curve points over F2m
     */
    public static class F2m extends ECPoint
    {
        private boolean withCompression;
        
        /**
         * @param curve base curve
         * @param x x point
         * @param y y point
         */
        public F2m(ECCurve curve, ECFieldElement x, ECFieldElement y)
        {
            this(curve, x, y, false);
        }
        
        /**
         * @param curve base curve
         * @param x x point
         * @param y y point
         * @param withCompression true if encode with point compression.
         */
        public F2m(ECCurve curve, ECFieldElement x, ECFieldElement y, boolean withCompression)
        {
            super(curve, x, y);

            if (x != null && y == null)
            {
                throw new IllegalArgumentException("wrong field element passed");
            }
            
            if (x == null && y != null)
            {
                throw new IllegalArgumentException("wrong field element passed");
            }

            if (x != null)
            {
                // Check if x and y are elements of the same field
                ECFieldElement.F2m.checkFieldElements(this.x, this.y);
    
                // Check if x and a are elements of the same field
                ECFieldElement.F2m.checkFieldElements(this.x, this.curve.getA());
            }
            
            this.withCompression = withCompression;
        }

        /**
         * Constructor for point at infinity
         */
        public F2m(ECCurve curve)
        {
            super(curve, null, null);
        }

        /* (non-Javadoc)
         * @see org.bouncycastle.math.ec.ECPoint#getEncoded()
         */
        public byte[] getEncoded()
        {
            if (isInfinity()) 
            {
                throw new RuntimeException("Point at infinity cannot be encoded");
            }

            if (withCompression)
            {
                throw new RuntimeException("not implemented");
            }
            else
            {
                int m = ((ECFieldElement.F2m)x).getM();
                int byteCount = m/8;
                if (m % 8 > 0) 
                {
                    byteCount++;
                }
    
                byte[] X = converter.integerToBytes(this.getX().toBigInteger(), byteCount);
                byte[] Y = converter.integerToBytes(this.getY().toBigInteger(), byteCount);
    
                byte[]  PO = new byte[byteCount + byteCount + 1];
    
                PO[0] = 0x04;
                System.arraycopy(X, 0, PO, 1, byteCount);
                System.arraycopy(Y, 0, PO, byteCount + 1, byteCount);
    
                return PO;
            }
        }

        /* (non-Javadoc)
         * @see org.bouncycastle.math.ec.ECPoint#add(org.bouncycastle.math.ec.ECPoint)
         */
        public ECPoint add(ECPoint b)
        {
            // Check, if points are on the same curve
            if (!(curve.equals(b.getCurve())))
            {
                throw new IllegalArgumentException("Only points on the same "
                        + "curve can be added");
            }

            if (isInfinity())
            {
                if (b.isInfinity())
                {
                    return new ECPoint.F2m(curve);
                }
                return new ECPoint.F2m(b.getCurve(), b.getX(), b.getY(), withCompression);
            }

            if (b.isInfinity())
            {
                return new ECPoint.F2m(curve, x, y, withCompression);
            }

            ECFieldElement.F2m.checkFieldElements(x, b.getX());
            ECFieldElement.F2m x2 = (ECFieldElement.F2m)b.getX();
            ECFieldElement.F2m y2 = (ECFieldElement.F2m)b.getY();

            // Check if b = this or b = -this
            if (x.equals(x2))
            {
                if (y.equals(y2))
                {
                    // this = b, i.e. this must be doubled
                    return this.twice();
                }
                else
                {
                    // this = -b, i.e. the result is the point at infinity
                    return new ECPoint.F2m(curve);
                }
            }

            ECFieldElement.F2m lambda
                = (ECFieldElement.F2m)(y.add(y2)).divide(x.add(x2));

            ECFieldElement.F2m x3
                = (ECFieldElement.F2m)lambda.square().add(lambda).add(x).add(x2).add(curve.getA());

            ECFieldElement.F2m y3
                = (ECFieldElement.F2m)lambda.multiply(x.add(x3)).add(x3).add(y);

            return new ECPoint.F2m(curve, x3, y3, withCompression);
        }

        /* (non-Javadoc)
         * @see org.bouncycastle.math.ec.ECPoint#subtract(org.bouncycastle.math.ec.ECPoint)
         */
        public ECPoint subtract(ECPoint b)
        {
            // Add -b
            ECPoint.F2m minusB
                = new ECPoint.F2m(curve, b.getX(), b.getY().negate(), withCompression);
            return add(minusB);
        }

        /* (non-Javadoc)
         * @see org.bouncycastle.math.ec.ECPoint#twice()
         */
        public ECPoint twice()
        {
            if (isInfinity() || (x.toBigInteger().equals(BigInteger.ZERO))) 
            {
                // Twice identity element (point at infinity) is identity
                // element, and if x1 == null, then (x1, y1) == (x1, x1 + y1)
                // and hence this = -this and thus 2(x1, y1) == infinity
                return new ECPoint.F2m(curve);
            }

            ECFieldElement.F2m lambda
                = (ECFieldElement.F2m)x.add(y.divide(x));

            ECFieldElement.F2m x3
                = (ECFieldElement.F2m)lambda.square().add(lambda).
                    add(curve.getA());

            ECFieldElement.F2m y3
                = (ECFieldElement.F2m)x.square().add(lambda.multiply(x3)).
                    add(x3);

            return new ECPoint.F2m(curve, x3, y3, withCompression);
        }

        public ECPoint multiply(
            BigInteger k)
        {
            ECPoint.F2m p = this;
            ECPoint.F2m q = new ECPoint.F2m(curve);
            int t = k.bitLength();
            for (int i = 0; i < t; i++) 
            {
                if (k.testBit(i)) 
                {
                    q = (ECPoint.F2m)q.add(p);
                }
                p = (ECPoint.F2m)p.twice();
            }
            return q;
        }
    }
}
