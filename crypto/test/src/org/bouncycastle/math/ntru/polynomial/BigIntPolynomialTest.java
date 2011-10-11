package org.bouncycastle.math.ntru.polynomial;

import java.math.BigInteger;

import junit.framework.TestCase;

public class BigIntPolynomialTest
    extends TestCase
{
    public void testMult()
    {
        BigIntPolynomial a = new BigIntPolynomial(new IntegerPolynomial(new int[]{4, -1, 9, 2, 1, -5, 12, -7, 0, -9, 5}));
        BigIntPolynomial b = new BigIntPolynomial(new IntegerPolynomial(new int[]{-6, 0, 0, 13, 3, -2, -4, 10, 11, 2, -1}));
        BigIntPolynomial c = a.mult(b);
        BigInteger[] expectedCoeffs = new BigIntPolynomial(new IntegerPolynomial(new int[]{2, -189, 77, 124, -29, 0, -75, 124, -49, 267, 34})).coeffs;

        assertEquals(expectedCoeffs.length, c.coeffs.length);
        for (int i = 0; i != c.coeffs.length; i++)
        {
            assertEquals(expectedCoeffs[i], c.coeffs[i]);
        }
    }
}