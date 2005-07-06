package org.bouncycastle.math.ec;

import java.math.BigInteger;

public abstract class ECCurve
{
	BigInteger q;
	ECFieldElement a, b;

	public ECCurve(BigInteger q, BigInteger a, BigInteger b)
	{
		this.q = q;
		this.a = fromBigInteger(a);
		this.b = fromBigInteger(b);
	}

	public abstract ECFieldElement fromBigInteger(BigInteger x);

	public abstract ECPoint decodePoint(byte[] encoded);

    public ECFieldElement getA()
    {
        return a;
    }

    public ECFieldElement getB()
    {
        return b;
    }
}
