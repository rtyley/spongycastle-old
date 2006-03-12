package org.bouncycastle.jce.provider;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.EllipticCurve;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKeyStructure;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.jce.interfaces.ECPointEncoder;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;

public class JCEECPrivateKey
    implements ECPrivateKey, org.bouncycastle.jce.interfaces.ECPrivateKey, PKCS12BagAttributeCarrier, ECPointEncoder
{
    private String          algorithm = "EC";
    private BigInteger      d;
    private ECParameterSpec ecSpec;
    private boolean         withCompression;

    private Hashtable   pkcs12Attributes = new Hashtable();
    private Vector      pkcs12Ordering = new Vector();

    protected JCEECPrivateKey()
    {
    }

    JCEECPrivateKey(
        ECPrivateKey    key)
    {
        this.d = key.getS();
        this.algorithm = key.getAlgorithm();
        this.ecSpec = key.getParams();
    }

    JCEECPrivateKey(
        String              algorithm,
        org.bouncycastle.jce.spec.ECPrivateKeySpec     spec)
    {
        this.algorithm = algorithm;
        this.d = spec.getD();
        
        ECCurve curve = spec.getParams().getCurve();
        EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, spec.getParams().getSeed());
        
        this.ecSpec = new ECParameterSpec(
                                ellipticCurve,
                                new ECPoint(
                                        spec.getParams().getG().getX().toBigInteger(),
                                        spec.getParams().getG().getY().toBigInteger()),
                                spec.getParams().getN(),
                                spec.getParams().getH().intValue());
    }


    JCEECPrivateKey(
        String              algorithm,
        ECPrivateKeySpec    spec)
    {
        this.algorithm = algorithm;
        this.d = spec.getS();
        this.ecSpec = spec.getParams();
    }

    JCEECPrivateKey(
        String                  algorithm,
        ECPrivateKeyParameters  params,
        ECParameterSpec         spec)
    {
        ECDomainParameters      dp = params.getParameters();

        this.algorithm = algorithm;
        this.d = params.getD();

        if (spec == null)
        {
            EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

            this.ecSpec = new ECParameterSpec(
                            ellipticCurve,
                            new ECPoint(
                                    dp.getG().getX().toBigInteger(),
                                    dp.getG().getY().toBigInteger()),
                            dp.getN(),
                            dp.getH().intValue());
        }
        else
        {
            this.ecSpec = spec;
        }
    }

    JCEECPrivateKey(
        String                  algorithm,
        ECPrivateKeyParameters  params,
        org.bouncycastle.jce.spec.ECParameterSpec         spec)
    {
        ECDomainParameters      dp = params.getParameters();

        this.algorithm = algorithm;
        this.d = params.getD();

        if (spec == null)
        {
            EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

            this.ecSpec = new ECParameterSpec(
                            ellipticCurve,
                            new ECPoint(
                                    dp.getG().getX().toBigInteger(),
                                    dp.getG().getY().toBigInteger()),
                            dp.getN(),
                            dp.getH().intValue());
        }
        else
        {
            EllipticCurve ellipticCurve = EC5Util.convertCurve(spec.getCurve(), spec.getSeed());
            
            this.ecSpec = new ECParameterSpec(
                                ellipticCurve,
                                new ECPoint(
                                        spec.getG().getX().toBigInteger(),
                                        spec.getG().getY().toBigInteger()),
                                spec.getN(),
                                spec.getH().intValue());
        }
    }

    JCEECPrivateKey(
        PrivateKeyInfo      info)
    {
        X962Parameters      params = new X962Parameters((DERObject)info.getAlgorithmId().getParameters());

        if (params.isNamedCurve())
        {
            DERObjectIdentifier oid = (DERObjectIdentifier)params.getParameters();
            X9ECParameters      ecP = ECUtil.getNamedCurveByOid(oid);
            EllipticCurve       ellipticCurve = EC5Util.convertCurve(ecP.getCurve(), ecP.getSeed());

            ecSpec = new ECNamedCurveSpec(
                    ECUtil.getCurveName(oid),
                    ellipticCurve,
                    new ECPoint(
                            ecP.getG().getX().toBigInteger(),
                            ecP.getG().getY().toBigInteger()),
                    ecP.getN(),
                    ecP.getH());
        }
        else
        {
            X9ECParameters      ecP = new X9ECParameters((ASN1Sequence)params.getParameters());
            EllipticCurve       ellipticCurve = EC5Util.convertCurve(ecP.getCurve(), ecP.getSeed());

            this.ecSpec = new ECParameterSpec(
                ellipticCurve,
                new ECPoint(
                        ecP.getG().getX().toBigInteger(),
                        ecP.getG().getY().toBigInteger()),
                ecP.getN(),
                ecP.getH().intValue());
        }

        if (info.getPrivateKey() instanceof DERInteger)
        {
            DERInteger          derD = (DERInteger)info.getPrivateKey();

            this.d = derD.getValue();
        }
        else
        {
            ECPrivateKeyStructure   ec = new ECPrivateKeyStructure((ASN1Sequence)info.getPrivateKey());

            this.d = ec.getKey();
        }
    }

    public String getAlgorithm()
    {
        return algorithm;
    }

    /**
     * return the encoding format we produce in getEncoded().
     *
     * @return the string "PKCS#8"
     */
    public String getFormat()
    {
        return "PKCS#8";
    }

    /**
     * Return a PKCS8 representation of the key. The sequence returned
     * represents a full PrivateKeyInfo object.
     *
     * @return a PKCS8 representation of the key.
     */
    public byte[] getEncoded()
    {
        X962Parameters          params = null;

        if (ecSpec instanceof ECNamedCurveSpec)
        {
            DERObjectIdentifier curveOid = ECUtil.getNamedCurveOid(((ECNamedCurveSpec)ecSpec).getName());
            
            params = new X962Parameters(curveOid);
        }
        else
        {
            ECField field = ecSpec.getCurve().getField();
            ECCurve curve;
            org.bouncycastle.math.ec.ECPoint ecPoint;

            if (field instanceof ECFieldFp)
            {
                curve = new ECCurve.Fp(((ECFieldFp)field).getP(), ecSpec.getCurve().getA(), ecSpec.getCurve().getB());
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

            X9ECParameters          ecP = new X9ECParameters(
                                            curve,
                                            ecPoint,
                                            ecSpec.getOrder(),
                                            BigInteger.valueOf(ecSpec.getCofactor()),
                                            ecSpec.getCurve().getSeed());
            
            params = new X962Parameters(ecP);
        }
        
        PrivateKeyInfo          info;
        
        if (algorithm.equals("ECGOST3410"))
        {
            info = new PrivateKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001, params.getDERObject()), new ECPrivateKeyStructure(this.getS()).getDERObject());
        }
        else
        {
            info = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params.getDERObject()), new ECPrivateKeyStructure(this.getS()).getDERObject());
        }

        return info.getDEREncoded();
    }

    public ECParameterSpec getParams()
    {
        return ecSpec;
    }

    public org.bouncycastle.jce.spec.ECParameterSpec getParameters()
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
    
    public BigInteger getS()
    {
        return d;
    }

    public BigInteger getD()
    {
        return d;
    }
    
    public void setBagAttribute(
        DERObjectIdentifier oid,
        DEREncodable        attribute)
    {
        pkcs12Attributes.put(oid, attribute);
        pkcs12Ordering.addElement(oid);
    }

    public DEREncodable getBagAttribute(
        DERObjectIdentifier oid)
    {
        return (DEREncodable)pkcs12Attributes.get(oid);
    }

    public Enumeration getBagAttributeKeys()
    {
        return pkcs12Ordering.elements();
    }

    public void setPointFormat(String style)
    {
       withCompression = !("UNCOMPRESSED".equalsIgnoreCase(style));
    }
}
