package org.bouncycastle.jce.provider;

import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;

import java.math.BigInteger;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

public class EC5Util
{
    static EllipticCurve convertCurve(
        ECCurve curve, 
        byte[]  seed)
    {
        if (curve instanceof ECCurve.Fp)
        {
            return new EllipticCurve(new ECFieldFp(((ECCurve.Fp)curve).getQ()), curve.getA().toBigInteger(), curve.getB().toBigInteger(), seed);
        }
        else
        {
            ECCurve.F2m curveF2m = (ECCurve.F2m)curve;
            int ks[];
            
            if (curveF2m.isTrinomial())
            {
                ks = new int[] { curveF2m.getK1() };
                
                return new EllipticCurve(new ECFieldF2m(curveF2m.getM(), ks), curve.getA().toBigInteger(), curve.getB().toBigInteger(), seed);
            }
            else
            {
                ks = new int[] { curveF2m.getK3(), curveF2m.getK2(), curveF2m.getK1() };
                
                return new EllipticCurve(new ECFieldF2m(curveF2m.getM(), ks), curve.getA().toBigInteger(), curve.getB().toBigInteger(), seed);
            } 
        }
    }
    

    static ECParameterSpec convertSpec(
        EllipticCurve ellipticCurve,
        org.bouncycastle.jce.spec.ECParameterSpec spec)
    {
        if (spec instanceof ECNamedCurveParameterSpec)
        {
            return new ECNamedCurveSpec(
                ((ECNamedCurveParameterSpec)spec).getName(),
                ellipticCurve,
                new ECPoint(
                        spec.getG().getX().toBigInteger(),
                        spec.getG().getY().toBigInteger()),
                        spec.getN(),
                        spec.getH());
        }
        else
        {
            return new ECParameterSpec(
                ellipticCurve,
                new ECPoint(
                        spec.getG().getX().toBigInteger(),
                        spec.getG().getY().toBigInteger()),
                        spec.getN(),
                        spec.getH().intValue());
        }
    }

    static org.bouncycastle.jce.spec.ECParameterSpec convertSpec(
        ECParameterSpec ecSpec,
        boolean withCompression)
    {
        ECCurve curve;
        org.bouncycastle.math.ec.ECPoint ecPoint;
        ECField field = ecSpec.getCurve().getField();

        if (field instanceof ECFieldFp)
        {
            curve = new ECCurve.Fp(((ECFieldFp)ecSpec.getCurve().getField()).getP(), ecSpec.getCurve().getA(), ecSpec.getCurve().getB());
            ecPoint = new org.bouncycastle.math.ec.ECPoint.Fp(curve, new ECFieldElement.Fp(((ECCurve.Fp)curve).getQ(), ecSpec.getGenerator().getAffineX()), new ECFieldElement.Fp(((ECCurve.Fp)curve).getQ(), ecSpec.getGenerator().getAffineY()), withCompression);
        }
        else
        {
            ECFieldF2m fieldF2m = (ECFieldF2m)field;
            int m = fieldF2m.getM();
            int ks[] = ECUtil.convertMidTerms(fieldF2m.getMidTermsOfReductionPolynomial());
            curve = new ECCurve.F2m(m, ks[0], ks[1], ks[2], ecSpec.getCurve().getA(), ecSpec.getCurve().getB());
            ecPoint = new org.bouncycastle.math.ec.ECPoint.F2m(curve, new ECFieldElement.F2m(m, ks[0], ks[1], ks[2], ecSpec.getGenerator().getAffineX()), new ECFieldElement.F2m(m, ks[0], ks[1], ks[2], ecSpec.getGenerator().getAffineY()), withCompression);
        }

        return new org.bouncycastle.jce.spec.ECParameterSpec(
                curve,
                ecPoint,
                ecSpec.getOrder(),
                BigInteger.valueOf(ecSpec.getCofactor()),
                ecSpec.getCurve().getSeed());
    }
}
