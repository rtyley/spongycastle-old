package org.spongycastle.math.ec;

import java.math.BigInteger;

public abstract class ECFieldElement
    implements ECConstants
{
	BigInteger x;
	BigInteger p;

	public ECFieldElement(BigInteger q, BigInteger x)
	{
        if (x.compareTo(q) >= 0)
        {
            throw new IllegalArgumentException("x value of field element too large");
        }

		this.x = x;
		this.p = q; // curve.getQ();
	}

	public BigInteger toBigInteger()
	{
		return x;
	}

	public boolean equals(Object other)
	{
		if ( other == this )
			return true;

		if ( !(other instanceof ECFieldElement) )
			return false;

		ECFieldElement o = (ECFieldElement)other;

		return p.equals(o.p) && x.equals(o.x);
	}

	public abstract String         getFieldName();
	public abstract ECFieldElement add(ECFieldElement b);
	public abstract ECFieldElement subtract(ECFieldElement b);
	public abstract ECFieldElement multiply(ECFieldElement b);
	public abstract ECFieldElement divide(ECFieldElement b);
	public abstract ECFieldElement negate();
	public abstract ECFieldElement square();
	public abstract ECFieldElement invert();
	public abstract ECFieldElement sqrt();
}
