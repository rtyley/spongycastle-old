package org.bouncycastle.jce.provider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.ECGOST3410NamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPointEncoder;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;

public class JCEECPublicKey
    implements ECPublicKey, org.bouncycastle.jce.interfaces.ECPublicKey, ECPointEncoder
{
    private String                  algorithm = "EC";
    private org.bouncycastle.math.ec.ECPoint                 q;
    private ECParameterSpec         ecSpec;
    private boolean                 withCompression = true;
    private GOST3410PublicKeyAlgParameters       gostParams;

    JCEECPublicKey(
        String              algorithm,
        ECPublicKeySpec     spec)
    {
        this.algorithm = algorithm;
        this.ecSpec = spec.getParams();
        this.q = new org.bouncycastle.math.ec.ECPoint.Fp(new ECCurve.Fp(((ECFieldFp)ecSpec.getCurve().getField()).getP(), ecSpec.getCurve().getA(), ecSpec.getCurve().getB()), new ECFieldElement.Fp(((ECFieldFp)ecSpec.getCurve().getField()).getP(), spec.getW().getAffineX()), new ECFieldElement.Fp(((ECFieldFp)ecSpec.getCurve().getField()).getP(), spec.getW().getAffineY()));
    }

    JCEECPublicKey(
        String              algorithm,
        org.bouncycastle.jce.spec.ECPublicKeySpec     spec)
    {
        this.algorithm = algorithm;
        this.q = spec.getQ();
        
        ECCurve.Fp    curve = (ECCurve.Fp)spec.getParams().getCurve();
        this.ecSpec = new ECParameterSpec(
                                new EllipticCurve(new ECFieldFp(curve.getQ()), curve.getA().toBigInteger(), curve.getB().toBigInteger(), spec.getParams().getSeed()),
                                new ECPoint(
                                        spec.getParams().getG().getX().toBigInteger(),
                                        spec.getParams().getG().getY().toBigInteger()),
                                spec.getParams().getN(),
                                spec.getParams().getH().intValue());
    }
    
    JCEECPublicKey(
        String                  algorithm,
        ECPublicKeyParameters   params,
        ECParameterSpec         spec)
    {
        ECDomainParameters      dp = params.getParameters();

        this.algorithm = algorithm;
        this.q = params.getQ();

        if (spec == null)
        {
            ECCurve.Fp curve = (ECCurve.Fp)dp.getCurve();
            
            this.ecSpec = new ECParameterSpec(
                            new EllipticCurve(new ECFieldFp(curve.getQ()), curve.getA().toBigInteger(), curve.getB().toBigInteger(), dp.getSeed()),
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

    JCEECPublicKey(
        String                  algorithm,
        ECPublicKeyParameters   params,
        org.bouncycastle.jce.spec.ECParameterSpec         spec)
    {
        ECDomainParameters      dp = params.getParameters();

        this.algorithm = algorithm;
        this.q = params.getQ();

        if (spec == null)
        {
            ECCurve.Fp curve = (ECCurve.Fp)dp.getCurve();
            
            this.ecSpec = new ECParameterSpec(
                            new EllipticCurve(new ECFieldFp(curve.getQ()), curve.getA().toBigInteger(), curve.getB().toBigInteger(), dp.getSeed()),
                            new ECPoint(
                                    dp.getG().getX().toBigInteger(),
                                    dp.getG().getY().toBigInteger()),
                            dp.getN(),
                            dp.getH().intValue());
        }
        else
        {
            ECCurve.Fp    curve = (ECCurve.Fp)spec.getCurve();
            this.ecSpec = new ECParameterSpec(
                                    new EllipticCurve(new ECFieldFp(curve.getQ()), curve.getA().toBigInteger(), curve.getB().toBigInteger(), spec.getSeed()),
                                    new ECPoint(
                                            spec.getG().getX().toBigInteger(),
                                            spec.getG().getY().toBigInteger()),
                                    spec.getN(),
                                    spec.getH().intValue());
        }
    }
    
    JCEECPublicKey(
        String          algorithm,
        ECPublicKey     key)
    {
        this.algorithm = key.getAlgorithm();
        this.ecSpec = key.getParams();
        this.q = new org.bouncycastle.math.ec.ECPoint.Fp(new ECCurve.Fp(((ECFieldFp)ecSpec.getCurve().getField()).getP(), ecSpec.getCurve().getA(), ecSpec.getCurve().getB()), new ECFieldElement.Fp(((ECFieldFp)ecSpec.getCurve().getField()).getP(), key.getW().getAffineX()), new ECFieldElement.Fp(((ECFieldFp)ecSpec.getCurve().getField()).getP(), key.getW().getAffineY()));
    }

    JCEECPublicKey(
        SubjectPublicKeyInfo    info)
    {
        if (info.getAlgorithmId().getObjectId().equals(CryptoProObjectIdentifiers.gostR3410_2001))
        {
            DERBitString    bits = info.getPublicKeyData();
            ASN1OctetString key;
            this.algorithm = "ECGOST3410";
            
            try
            {
                ASN1InputStream         aIn = new ASN1InputStream(bits.getBytes());

                key = (ASN1OctetString)aIn.readObject();
            }
            catch (IOException ex)
            {
                throw new IllegalArgumentException("error recovering public key");
            }

            byte[]          keyEnc = key.getOctets();
            byte[]          x = new byte[32];
            byte[]          y = new byte[32];

            for (int i = 0; i != y.length; i++)
            {
                x[i] = keyEnc[32 - 1 - i];
            }
            
            for (int i = 0; i != x.length; i++)
            {
                y[i] = keyEnc[64 - 1 - i];
            }

            gostParams = new GOST3410PublicKeyAlgParameters((ASN1Sequence)info.getAlgorithmId().getParameters());
            
            ECNamedCurveParameterSpec spec = ECGOST3410NamedCurveTable.getParameterSpec(ECGOST3410NamedCurves.getName(gostParams.getPublicKeyParamSet()));

            ECCurve.Fp curve = (ECCurve.Fp)spec.getCurve();
            
            ecSpec = new ECNamedCurveSpec(
                            ECGOST3410NamedCurves.getName(gostParams.getPublicKeyParamSet()),
                            new EllipticCurve(new ECFieldFp(curve.getQ()), curve.getA().toBigInteger(), curve.getB().toBigInteger()),
                            new ECPoint(
                                    spec.getG().getX().toBigInteger(),
                                    spec.getG().getY().toBigInteger()),
                            spec.getN());
                            
            this.q = new org.bouncycastle.math.ec.ECPoint.Fp(curve, new ECFieldElement.Fp(curve.getQ(), new BigInteger(1, x)), new ECFieldElement.Fp(curve.getQ(), new BigInteger(1, y)));
        }
        else
        {
            X962Parameters          params = new X962Parameters((DERObject)info.getAlgorithmId().getParameters());
            ECCurve.Fp              curve;
            
            if (params.isNamedCurve())
            {
                DERObjectIdentifier oid = (DERObjectIdentifier)params.getParameters();
                X9ECParameters      ecP = X962NamedCurves.getByOID(oid);
    
                curve = (ECCurve.Fp)ecP.getCurve();
                ecSpec = new ECNamedCurveSpec(
                        X962NamedCurves.getName(oid),
                        new EllipticCurve(new ECFieldFp(curve.getQ()), curve.getA().toBigInteger(), curve.getB().toBigInteger(), ecP.getSeed()),
                        new ECPoint(
                                ecP.getG().getX().toBigInteger(),
                                ecP.getG().getY().toBigInteger()),
                        ecP.getN(),
                        ecP.getH());
            }
            else
            {
                X9ECParameters          ecP = new X9ECParameters((ASN1Sequence)params.getParameters());
                
                curve = (ECCurve.Fp)ecP.getCurve();
                this.ecSpec = new ECParameterSpec(
                        new EllipticCurve(new ECFieldFp(curve.getQ()), curve.getA().toBigInteger(), curve.getB().toBigInteger(), ecP.getSeed()),
                        new ECPoint(
                                ecP.getG().getX().toBigInteger(),
                                ecP.getG().getY().toBigInteger()),
                        ecP.getN(),
                        ecP.getH().intValue());
            }
    
            DERBitString    bits = info.getPublicKeyData();
            byte[]          data = bits.getBytes();
            ASN1OctetString key = new DEROctetString(data);
    
            //
            // extra octet string - one of our old certs...
            //
            if (data[0] == 0x04 && data[1] == data.length - 2 
                && (data[2] == 0x02 || data[2] == 0x03))
            {
                try
                {
                    ByteArrayInputStream    bIn = new ByteArrayInputStream(data);
                    ASN1InputStream         aIn = new ASN1InputStream(bIn);
    
                    key = (ASN1OctetString)aIn.readObject();
                }
                catch (IOException ex)
                {
                    throw new IllegalArgumentException("error recovering public key");
                }
            }
            X9ECPoint       derQ = new X9ECPoint(curve, key);
    
            this.q = derQ.getPoint();
        }
    }

    public String getAlgorithm()
    {
        return algorithm;
    }

    public String getFormat()
    {
        return "X.509";
    }

    public byte[] getEncoded()
    {
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        DEROutputStream         dOut = new DEROutputStream(bOut);
        ASN1Encodable           params = null;

        if (algorithm.equals("ECGOST3410"))
        {
            params = new DERNull();  // TODO - parameters not yet correct
        }
        else
        {
	        if (ecSpec instanceof ECNamedCurveSpec)
	        {
	            params = new X962Parameters(X962NamedCurves.getOID(((ECNamedCurveSpec)ecSpec).getName()));
	        }
	        else
	        {
	            ECCurve.Fp              curve = new ECCurve.Fp(((ECFieldFp)ecSpec.getCurve().getField()).getP(), ecSpec.getCurve().getA(), ecSpec.getCurve().getB());
	            X9ECParameters          ecP = new X9ECParameters(
	                                            curve,
	                                            new org.bouncycastle.math.ec.ECPoint.Fp(curve, curve.fromBigInteger(ecSpec.getGenerator().getAffineX()), curve.fromBigInteger(ecSpec.getGenerator().getAffineY()), withCompression),
	                                            ecSpec.getOrder(),
	                                            BigInteger.valueOf(ecSpec.getCofactor()),
	                                            ecSpec.getCurve().getSeed());
	            
	            params = new X962Parameters(ecP);
	        }
        }

        SubjectPublicKeyInfo info;
        
        if (algorithm.equals("ECGOST3410"))
        {
            ASN1OctetString    p = (ASN1OctetString)(new X9ECPoint(new org.bouncycastle.math.ec.ECPoint.Fp(this.getQ().getCurve(), this.getQ().getX(), this.getQ().getY(), false)).getDERObject());
            
            BigInteger      bX = this.q.getX().toBigInteger();
            BigInteger      bY = this.q.getY().toBigInteger();
            byte[]          encKey = new byte[64];
            
            byte[] val = bX.toByteArray();
            
            for (int i = 0; i != 32; i++)
            {
                encKey[i] = val[val.length - 1 - i];
            }
            
            val = bY.toByteArray();
            
            for (int i = 0; i != 32; i++)
            {
                encKey[32 + i] = val[val.length - 1 - i];
            }
            
            info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001, gostParams.getDERObject()), new DEROctetString(encKey));
        }
        else
        {
            ASN1OctetString    p = (ASN1OctetString)(new X9ECPoint(new org.bouncycastle.math.ec.ECPoint.Fp(this.getQ().getCurve(), this.getQ().getX(), this.getQ().getY(), withCompression)).getDERObject());
            
            info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params.getDERObject()), p.getOctets());
        }
        
        try
        {
            dOut.writeObject(info);
            dOut.close();
        }
        catch (IOException e)
        {
            throw new RuntimeException("Error encoding EC public key");
        }

        return bOut.toByteArray();
    }

    public ECParameterSpec getParams()
    {
        return ecSpec;
    }

    public org.bouncycastle.jce.spec.ECParameterSpec getParameters()
    {
        ECCurve.Fp              curve = new ECCurve.Fp(((ECFieldFp)ecSpec.getCurve().getField()).getP(), ecSpec.getCurve().getA(), ecSpec.getCurve().getB());
        
        return new org.bouncycastle.jce.spec.ECParameterSpec(
                curve,
                new org.bouncycastle.math.ec.ECPoint.Fp(curve, curve.fromBigInteger(ecSpec.getGenerator().getAffineX()), curve.fromBigInteger(ecSpec.getGenerator().getAffineY())),
                ecSpec.getOrder(),
                BigInteger.valueOf(ecSpec.getCofactor()),
                ecSpec.getCurve().getSeed());
    }
    
    public ECPoint getW()
    {
        return new ECPoint(q.getX().toBigInteger(), q.getY().toBigInteger());
    }

    public org.bouncycastle.math.ec.ECPoint getQ()
    {
        return q;
    }
    
    public String toString()
    {
        StringBuffer    buf = new StringBuffer();
        String          nl = System.getProperty("line.separator");

        buf.append("EC Public Key" + nl);
        buf.append("            X: " + this.q.getX().toBigInteger().toString(16) + nl);
        buf.append("            Y: " + this.q.getY().toBigInteger().toString(16) + nl);

        return buf.toString();

    }
    
    public void setPointFormat(String style)
    {
       withCompression = !("UNCOMPRESSED".equals(style));
    }
}
