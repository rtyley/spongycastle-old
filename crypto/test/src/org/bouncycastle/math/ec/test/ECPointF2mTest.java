package org.bouncycastle.math.ec.test;

import java.math.BigInteger;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

public class ECPointF2mTest extends TestCase
{
	// Irreducible polynomial for TPB z^4 + z + 1
	public final int m = 4;

	public final int k1 = 1;

	// a = z^3
	public final ECFieldElement.F2m aTpb = new ECFieldElement.F2m(m, k1,
	        new BigInteger("1000", 2));

	// b = z^3 + 1
	public final ECFieldElement.F2m bTpb = new ECFieldElement.F2m(m, k1,
	        new BigInteger("1001", 2));

	public final ECCurve.F2m curveTpb = new ECCurve.F2m(m, k1, aTpb
	        .toBigInteger(), bTpb.toBigInteger());

	// x1 = z
	public final ECFieldElement.F2m x1 = new ECFieldElement.F2m(m, k1,
	        new BigInteger("0010", 2));

	// y1 = z^3 + z^2 + z + 1
	public final ECFieldElement.F2m y1 = new ECFieldElement.F2m(m, k1,
	        new BigInteger("1111", 2));

	public final ECPoint.F2m p1 = new ECPoint.F2m(curveTpb, x1, y1, false);

	// x2 = 0
	public final ECFieldElement.F2m x2 = new ECFieldElement.F2m(m, k1,
	        new BigInteger("1100", 2));

	// y2 = x2
	public final ECFieldElement.F2m y2 = x2;

	public final ECPoint.F2m p2 = new ECPoint.F2m(curveTpb, x2, y2, false);

	// x3 = 1
	public final ECFieldElement.F2m x3 = new ECFieldElement.F2m(m, k1,
	        new BigInteger("0001", 2));

	// y1 = x3
	public final ECFieldElement.F2m y3 = x3;

	public final ECPoint.F2m p3 = new ECPoint.F2m(curveTpb, x3, y3, false);

	// x4 = z^3 + z + 1
	public final ECFieldElement.F2m x4 = new ECFieldElement.F2m(m, k1,
	        new BigInteger("1011", 2));

	// y4 = z
	public final ECFieldElement.F2m y4 = new ECFieldElement.F2m(m, k1,
	        new BigInteger("0010", 2));

	public final ECPoint.F2m p4 = new ECPoint.F2m(curveTpb, x4, y4, false);

	// x5 = 0
	public final ECFieldElement.F2m x5 = new ECFieldElement.F2m(m, k1,
	        new BigInteger("0000", 2));

	// y4 = z^3 + z + 1
	public final ECFieldElement.F2m y5 = new ECFieldElement.F2m(m, k1,
	        new BigInteger("1011", 2));

	public final ECPoint.F2m p5 = new ECPoint.F2m(curveTpb, x5, y5, false);

	public final ECPoint.F2m infinityCurveTpb = new ECPoint.F2m(curveTpb);

	public void testInfinity()
	{
		final ECPoint.F2m twiceInfinity = (ECPoint.F2m) infinityCurveTpb
		        .twice();
		assertTrue("Twice infinity is not infinite", twiceInfinity.isInfinity());
		assertEquals("Twice infinity does not equal infinity",
		        infinityCurveTpb, twiceInfinity);

		final ECPoint.F2m doubleInfinity = (ECPoint.F2m) infinityCurveTpb
		        .add(twiceInfinity);
		assertTrue("Infinity plus infinity is not infinite", doubleInfinity
		        .isInfinity());

		final ECPoint.F2m p1PlusInfinity = (ECPoint.F2m) infinityCurveTpb
		        .add(p1);
		assertEquals("p1 plus infinity does not equal p1", p1, p1PlusInfinity);

		final ECPoint.F2m infinityPlusP1 = (ECPoint.F2m) p1
		        .add(infinityCurveTpb);
		assertEquals("p1 plus infinity does not equal p1", infinityPlusP1, p1);
	}

	public void testEquality()
	{
		assertEquals(infinityCurveTpb, infinityCurveTpb);
		assertEquals(infinityCurveTpb, (ECPoint.F2m) infinityCurveTpb.twice());

		assertEquals(p1, p1);
		assertEquals((ECPoint.F2m) p1.twice(), (ECPoint.F2m) p1.twice());

		assertFalse(infinityCurveTpb.equals(p1));
		assertFalse(p1.equals(infinityCurveTpb));
	}

	public void testAdd()
	{
		final ECPoint.F2m p1PlusP2 = (ECPoint.F2m) p1.add(p2);
		assertEquals("p1PlusP2 does not equal p3", p3, p1PlusP2);
	}

	public void testTwice()
	{
		final ECPoint.F2m p1Twice = (ECPoint.F2m) p1.twice();
		assertEquals("p1Twice does not equal p4", p4, p1Twice);
	}

	public void testAllPoints()
	{
		ECPoint.F2m lister = infinityCurveTpb;
		ECPoint.F2m lister1 = infinityCurveTpb;
		int i = 0;
		do
		{
			lister = (ECPoint.F2m) lister.add(p1);
			i++;
			lister1 = (ECPoint.F2m) p1.multiply(new BigInteger(Integer
			        .toString(i)));
			assertEquals("Add and Multiply do not correspond", lister, lister1);
		} while (!(lister.equals(infinityCurveTpb)));
	}

	public void testMultiply()
	{
		final ECPoint.F2m mult = (ECPoint.F2m) p1
		        .multiply(new BigInteger("22"));
	}

	public static Test suite()
	{
		return new TestSuite(ECPointF2mTest.class);
	}
}
