package org.bouncycastle.math.ec;

import java.math.BigInteger;

public abstract class ECPoint
{
    ECCurve         curve;
    ECFieldElement  x;
    ECFieldElement  y;

    public ECPoint(ECCurve curve, ECFieldElement x, ECFieldElement y)
    {
        this.curve = curve;
        this.x = x;
        this.y = y;
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

    public abstract byte[] getEncoded();

    public abstract ECPoint add(ECPoint b);
    public abstract ECPoint subtract(ECPoint b);
    public abstract ECPoint twice();
    public abstract ECPoint multiply(BigInteger b);
}
