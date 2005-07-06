package org.bouncycastle.jce.spec;

import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import org.bouncycastle.math.ec.ECCurve;

/**
 * specification signifying that the curve parameters can also be
 * referred to by name.
 */
public class ECNamedCurveSpec
    extends java.security.spec.ECParameterSpec
{
    private String  name;

    public ECNamedCurveSpec(
        String                              name,
        ECCurve                             curve,
        org.bouncycastle.math.ec.ECPoint    G,
        BigInteger                          n)
    {
        super(new EllipticCurve(new ECFieldFp(((ECCurve.Fp)curve).getQ()), curve.getA().toBigInteger(), curve.getB().toBigInteger()), new ECPoint(G.getX().toBigInteger(), G.getY().toBigInteger()), n, 1);

        this.name = name;
    }

    public ECNamedCurveSpec(
        String          name,
        EllipticCurve   curve,
        ECPoint         G,
        BigInteger      n)
    {
        super(curve, G, n, 1);

        this.name = name;
    }
    
    public ECNamedCurveSpec(
        String                              name,
        ECCurve                             curve,
        org.bouncycastle.math.ec.ECPoint    G,
        BigInteger                          n,
        BigInteger                          h)
    {
        super(new EllipticCurve(new ECFieldFp(((ECCurve.Fp)curve).getQ()), curve.getA().toBigInteger(), curve.getB().toBigInteger()), new ECPoint(G.getX().toBigInteger(), G.getY().toBigInteger()), n, h.intValue());

        this.name = name;
    }

    public ECNamedCurveSpec(
        String          name,
        EllipticCurve   curve,
        ECPoint         G,
        BigInteger      n,
        BigInteger      h)
    {
        super(curve, G, n, h.intValue());

        this.name = name;
    }
    
    public ECNamedCurveSpec(
        String                              name,
        ECCurve                             curve,
        org.bouncycastle.math.ec.ECPoint    G,
        BigInteger                          n,
        BigInteger                          h,
        byte[]                              seed)
    {
        super(new EllipticCurve(new ECFieldFp(((ECCurve.Fp)curve).getQ()), curve.getA().toBigInteger(), curve.getB().toBigInteger(), seed), new ECPoint(G.getX().toBigInteger(), G.getY().toBigInteger()), n, h.intValue());

        this.name = name;
    }

    /**
     * return the name of the curve the EC domain parameters belong to.
     */
    public String getName()
    {
        return name;
    }
}
