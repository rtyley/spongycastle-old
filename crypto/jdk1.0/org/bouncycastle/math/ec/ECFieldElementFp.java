package org.spongycastle.math.ec;

import java.math.BigInteger;

public class ECFieldElementFp extends ECFieldElement
{
    /**
     * return the field name for this field.
     *
     * @return the string "Fp".
     */
    public String getFieldName()
    {
        return "Fp";
    }

    public ECFieldElementFp(BigInteger q, BigInteger x)
    {
        super(q, x);
    }

    public ECFieldElement add(ECFieldElement b)
    {
        return new ECFieldElementFp(p, x.add(b.x).mod(p));
    }

    public ECFieldElement subtract(ECFieldElement b)
    {
        return new ECFieldElementFp(p, x.subtract(b.x).mod(p));
    }

    public ECFieldElement multiply(ECFieldElement b)
    {
        return new ECFieldElementFp(p, x.multiply(b.x).mod(p));
    }

    public ECFieldElement divide(ECFieldElement b)
    {
        return new ECFieldElementFp(p, x.multiply(b.x.modInverse(p)).mod(p));
    }

    public ECFieldElement negate()
    {
        return new ECFieldElementFp(p, x.negate().mod(p));
    }

    public ECFieldElement square()
    {
        return new ECFieldElementFp(p, x.multiply(x).mod(p));
    }

    public ECFieldElement invert()
    {
        return new ECFieldElementFp(p, x.modInverse(p));
    }

    // D.1.4 91
    public ECFieldElement sqrt()
    {
        // p mod 4 == 3
        if ( p.testBit(1) )
        {
            // z = g^(u+1) + p, p = 4u + 3
            ECFieldElement z = new ECFieldElementFp(p, x.modPow(p.shiftRight(2).add(ONE), p));

            return z.square().equals(this) ? z : null;
        }

        throw new RuntimeException("not done yet");
    }
}
