package org.bouncycastle.jce.provider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEREncodable;
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
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.ECUtil;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

public class JCEECPublicKey
    implements ECPublicKey, ECPointEncoder
{
    private String          algorithm = "EC";
    private ECPoint         q;
    private ECParameterSpec ecSpec;
    private boolean         withCompression;
    private GOST3410PublicKeyAlgParameters       gostParams;

    JCEECPublicKey(
        String              algorithm,
        JCEECPublicKey      key)
    {
        this.algorithm = algorithm;
        this.q = key.q;
        this.ecSpec = key.ecSpec;
        this.withCompression = key.withCompression;
        this.gostParams = key.gostParams;
    }

    JCEECPublicKey(
        String              algorithm,
        ECPublicKeySpec     spec)
    {
        this.algorithm = algorithm;
        this.q = spec.getQ();

        if (spec.getParams() != null)
        {
            this.ecSpec = spec.getParams();
        }
        else
        {
            if (q.getCurve() == null)
            {
                org.bouncycastle.jce.spec.ECParameterSpec s = ProviderUtil.getEcImplicitlyCa();

                q = (q instanceof org.bouncycastle.math.ec.ECPoint.Fp)
                                ? (org.bouncycastle.math.ec.ECPoint)new org.bouncycastle.math.ec.ECPoint.Fp(s.getCurve(), q.getX(), q.getY())
                                : (org.bouncycastle.math.ec.ECPoint)new org.bouncycastle.math.ec.ECPoint.F2m(s.getCurve(), q.getX(), q.getY());
            }
            this.ecSpec = null;
        }
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
            this.ecSpec = new ECParameterSpec(
                            dp.getCurve(),
                            dp.getG(),
                            dp.getN(),
                            dp.getH(),
                            dp.getSeed());
        }
        else
        {
            this.ecSpec = spec;
        }
    }

    JCEECPublicKey(
        String                  algorithm,
        ECPublicKeyParameters   params)
    {
        this.algorithm = algorithm;
        this.q = params.getQ();
        this.ecSpec = null;
    }

    JCEECPublicKey(
        ECPublicKey     key)
    {
        this.q = key.getQ();
        this.algorithm = key.getAlgorithm();
        this.ecSpec = key.getParameters();
    }

    JCEECPublicKey(
        String            algorithm,
        ECPoint           q,
        ECParameterSpec   ecSpec)
    {
        this.algorithm = algorithm;
        this.q = q;
        this.ecSpec = ecSpec;
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

            ecSpec = spec;

            ECCurve curve = spec.getCurve();
            if (curve instanceof ECCurve.Fp) 
            {
                ECCurve.Fp curveFp = (ECCurve.Fp) curve;
                this.q = new ECPoint.Fp(curveFp, new ECFieldElement.Fp(curveFp.getQ(), new BigInteger(1, x)), new ECFieldElement.Fp(curveFp.getQ(), new BigInteger(1, y)));
            } 
            else if (curve instanceof ECCurve.F2m) 
            {
                ECCurve.F2m curveF2m = (ECCurve.F2m) curve;
                int m = curveF2m.getM();
                int k1 = curveF2m.getK1();
                int k2 = curveF2m.getK2();
                int k3 = curveF2m.getK3();
                this.q = new ECPoint.F2m(curveF2m, new ECFieldElement.F2m(m, k1, k2, k3, new BigInteger(1, x)), new ECFieldElement.F2m(m, k1, k2, k3, new BigInteger(1, y)), false);
            }
            else 
            {
                throw new UnsupportedOperationException("Subclass of ECPoint " + curve.getClass().toString() + "not supported");
            }
        }
        else
        {
            X962Parameters          params = new X962Parameters((DERObject)info.getAlgorithmId().getParameters());
            ECCurve                 curve;

            if (params.isNamedCurve())
            {
                DERObjectIdentifier oid = (DERObjectIdentifier)params.getParameters();
                X9ECParameters      ecP = ECUtil.getNamedCurveByOid(oid);
    
                ecSpec = new ECNamedCurveParameterSpec(
                                            ECUtil.getCurveName(oid),
                                            ecP.getCurve(),
                                            ecP.getG(),
                                            ecP.getN(),
                                            ecP.getH(),
                                            ecP.getSeed());
                curve = ((ECParameterSpec)ecSpec).getCurve();
            }
            else if (params.isImplicitlyCA())
            {
                ecSpec = null;
                curve = ProviderUtil.getEcImplicitlyCa().getCurve();
            }
            else
            {
                X9ECParameters ecP = new X9ECParameters(
                            (ASN1Sequence)params.getParameters());
                ecSpec = new ECParameterSpec(
                                            ecP.getCurve(),
                                            ecP.getG(),
                                            ecP.getN(),
                                            ecP.getH(),
                                            ecP.getSeed());
                curve = ((ECParameterSpec)ecSpec).getCurve();
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
        SubjectPublicKeyInfo info;
        
        if (algorithm.equals("ECGOST3410"))
        {
            DEREncodable          params = null;
            if (gostParams != null)
            {
                params = gostParams;
            }
            else
            {
                params = new GOST3410PublicKeyAlgParameters(
                                   ECGOST3410NamedCurves.getOID(((ECNamedCurveParameterSpec)ecSpec).getName()),
                                   CryptoProObjectIdentifiers.gostR3411_94_CryptoProParamSet);
            }

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
            
            info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001, params.getDERObject()), new DEROctetString(encKey));
        }
        else
        {
            X962Parameters          params = null;
            if (ecSpec instanceof ECNamedCurveParameterSpec)
            {
                DERObjectIdentifier curveOid = ECUtil.getNamedCurveOid(((ECNamedCurveParameterSpec)ecSpec).getName());

                params = new X962Parameters(curveOid);
            }
            else if (ecSpec == null)
            {
                params = new X962Parameters(DERNull.INSTANCE);
            }
            else
            {
                ECParameterSpec         p = (ECParameterSpec)ecSpec;

                ECCurve curve = p.getG().getCurve();
                ECPoint generator;
                if (curve instanceof ECCurve.Fp)
                {
                    generator = new ECPoint.Fp(p.getG().getCurve(), p.getG().getX(), p.getG().getY(), withCompression);
                }
                else if (curve instanceof ECCurve.F2m)
                {
                    generator = new ECPoint.F2m(p.getG().getCurve(), p.getG().getX(), p.getG().getY(), withCompression);
                }
                else
                {
                    throw new UnsupportedOperationException("Subclass of ECPoint " + curve.getClass().toString() + "not supported");
                }

                X9ECParameters ecP = new X9ECParameters(
                    p.getCurve(), generator, p.getN(), p.getH(), p.getSeed());

                params = new X962Parameters(ecP);
            }

            ECCurve curve = this.engineGetQ().getCurve();
            ASN1OctetString p;
            if (curve instanceof ECCurve.Fp) 
            {
                p = (ASN1OctetString)(new X9ECPoint(new ECPoint.Fp(curve, this.getQ().getX(), this.getQ().getY(), withCompression)).getDERObject());
            } 
            else if (curve instanceof ECCurve.F2m)
            {
                p = (ASN1OctetString)(new X9ECPoint(new ECPoint.F2m(curve, this.getQ().getX(), this.getQ().getY(), withCompression)).getDERObject());
            } 
            else 
            {
                throw new UnsupportedOperationException("Subclass of ECPoint " + curve.getClass().toString() + "not supported");
            }
            
            info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params.getDERObject()), p.getOctets());
        }
        
        return info.getDEREncoded();
    }

    public ECParameterSpec getParams()
    {
        return (ECParameterSpec)ecSpec;
    }

    public ECParameterSpec getParameters()
    {
        return (ECParameterSpec)ecSpec;
    }
    
    public org.bouncycastle.math.ec.ECPoint getQ()
    {
        if (ecSpec == null)
        {
            if (q instanceof org.bouncycastle.math.ec.ECPoint.Fp)
            {
                return new org.bouncycastle.math.ec.ECPoint.Fp(null, q.getX(), q.getY());
            }
            else
            {
                return new org.bouncycastle.math.ec.ECPoint.F2m(null, q.getX(), q.getY());
            }
        }

        return q;
    }

    org.bouncycastle.math.ec.ECPoint engineGetQ()
    {
        return q;
    }

    public String toString()
    {
        StringBuffer    buf = new StringBuffer();
        String          nl = System.getProperty("line.separator");

        buf.append("EC Public Key").append(nl);
        buf.append("            X: ").append(this.getQ().getX().toBigInteger().toString(16)).append(nl);
        buf.append("            Y: ").append(this.getQ().getY().toBigInteger().toString(16)).append(nl);

        return buf.toString();

    }
/*
    private void readObject(
        ObjectInputStream   in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        boolean named = in.readBoolean();

        if (named)
        {
            ecSpec = new ECNamedCurveParameterSpec(
                        in.readUTF(),
                        (ECCurve)in.readObject(),
                        (ECPoint)in.readObject(),
                        (BigInteger)in.readObject(),
                        (BigInteger)in.readObject(),
                        (byte[])in.readObject());
        }
        else
        {
            ecSpec = new ECParameterSpec(
                        (ECCurve)in.readObject(),
                        (ECPoint)in.readObject(),
                        (BigInteger)in.readObject(),
                        (BigInteger)in.readObject(),
                        (byte[])in.readObject());
        }
    }

    private void writeObject(
        ObjectOutputStream  out)
        throws IOException
    {
        out.defaultWriteObject();

        if (this.ecSpec instanceof ECNamedCurveParameterSpec)
        {
            ECNamedCurveParameterSpec   namedSpec = (ECNamedCurveParameterSpec)ecSpec;

            out.writeBoolean(true);
            out.writeUTF(namedSpec.getName());
        }
        else
        {
            out.writeBoolean(false);
        }

        out.writeObject(ecSpec.getCurve());
        out.writeObject(ecSpec.getG());
        out.writeObject(ecSpec.getN());
        out.writeObject(ecSpec.getH());
        out.writeObject(ecSpec.getSeed());
    }
*/
    public void setPointFormat(String style)
    {
       withCompression = !("UNCOMPRESSED".equalsIgnoreCase(style));
    }

    ECParameterSpec engineGetSpec()
    {
        if (ecSpec != null)
        {
            return (ECParameterSpec)ecSpec;
        }

        return ProviderUtil.getEcImplicitlyCa();
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof JCEECPublicKey))
        {
            return false;
        }

        JCEECPublicKey other = (JCEECPublicKey)o;

        return getQ().equals(other.getQ()) && (engineGetSpec().equals(other.engineGetSpec()));
    }

    public int hashCode()
    {
        return getQ().hashCode() ^ engineGetSpec().hashCode();
    }
}
