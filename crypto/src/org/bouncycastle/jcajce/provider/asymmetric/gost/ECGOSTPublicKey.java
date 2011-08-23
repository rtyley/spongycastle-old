package org.bouncycastle.jcajce.provider.asymmetric.gost;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.ProviderUtil;
import org.bouncycastle.jcajce.provider.asymmetric.ec.EC5Util;
import org.bouncycastle.jce.ECGOST3410NamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;

public class ECGOSTPublicKey
    implements ECPublicKey //, ECPointEncoder
{
    private String algorithm = "EC";
    private org.bouncycastle.math.ec.ECPoint q;
    private ECParameterSpec ecSpec;
    private boolean                 withCompression;
    private GOST3410PublicKeyAlgParameters gostParams;

    public ECGOSTPublicKey(
        String algorithm,
        ECGOSTPublicKey key)
    {
        this.algorithm = algorithm;
        this.q = key.q;
        this.ecSpec = key.ecSpec;
        this.withCompression = key.withCompression;
        this.gostParams = key.gostParams;
    }
    
    public ECGOSTPublicKey(
        String algorithm,
        ECPublicKeySpec spec)
    {
        this.algorithm = algorithm;
        this.ecSpec = spec.getParams();
        this.q = EC5Util.convertPoint(ecSpec, spec.getW(), false);
    }
    
    public ECGOSTPublicKey(
        String algorithm,
        ECPublicKeyParameters params,
        ECParameterSpec spec)
    {
        ECDomainParameters dp = params.getParameters();

        this.algorithm = algorithm;
        this.q = params.getQ();

        if (spec == null)
        {
            EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

            this.ecSpec = createSpec(ellipticCurve, dp);
        }
        else
        {
            this.ecSpec = spec;
        }
    }

    /*
     * called for implicitCA
     */
    public ECGOSTPublicKey(
        String algorithm,
        ECPublicKeyParameters params)
    {
        this.algorithm = algorithm;
        this.q = params.getQ();
        this.ecSpec = null;
    }

    private ECParameterSpec createSpec(EllipticCurve ellipticCurve, ECDomainParameters dp)
    {
        return new ECParameterSpec(
                ellipticCurve,
                new ECPoint(
                        dp.getG().getX().toBigInteger(),
                        dp.getG().getY().toBigInteger()),
                        dp.getN(),
                        dp.getH().intValue());
    }
    
    public ECGOSTPublicKey(
        ECPublicKey key)
    {
        this.algorithm = key.getAlgorithm();
        this.ecSpec = key.getParams();
        this.q = EC5Util.convertPoint(this.ecSpec, key.getW(), false);
    }

    public ECGOSTPublicKey(
        SubjectPublicKeyInfo info)
    {
        populateFromPubKeyInfo(info);
    }

    private void populateFromPubKeyInfo(SubjectPublicKeyInfo info)
    {
        if (info.getAlgorithm().getAlgorithm().equals(CryptoProObjectIdentifiers.gostR3410_2001))
        {
            DERBitString bits = info.getPublicKeyData();
            ASN1OctetString key;
            this.algorithm = "ECGOST3410";

            key = ASN1OctetString.getInstance(bits.getBytes());


            byte[]          keyEnc = key.getOctets();
            byte[]          x = new byte[32];
            byte[]          y = new byte[32];

            for (int i = 0; i != x.length; i++)
            {
                x[i] = keyEnc[32 - 1 - i];
            }

            for (int i = 0; i != y.length; i++)
            {
                y[i] = keyEnc[64 - 1 - i];
            }

            gostParams = new GOST3410PublicKeyAlgParameters((ASN1Sequence)info.getAlgorithm().getParameters());

            ECNamedCurveParameterSpec spec = ECGOST3410NamedCurveTable.getParameterSpec(ECGOST3410NamedCurves.getName(gostParams.getPublicKeyParamSet()));

            ECCurve curve = spec.getCurve();
            EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, spec.getSeed());

            this.q = curve.createPoint(new BigInteger(1, x), new BigInteger(1, y), false);

            ecSpec = new ECNamedCurveSpec(
                    ECGOST3410NamedCurves.getName(gostParams.getPublicKeyParamSet()),
                    ellipticCurve,
                    new ECPoint(
                            spec.getG().getX().toBigInteger(),
                            spec.getG().getY().toBigInteger()),
                            spec.getN(), spec.getH());

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
        ASN1Encodable params;

        if (gostParams != null)
        {
            params = gostParams;
        }
        else
        {
            if (ecSpec instanceof ECNamedCurveSpec)
            {
                params = new GOST3410PublicKeyAlgParameters(
                               ECGOST3410NamedCurves.getOID(((ECNamedCurveSpec)ecSpec).getName()),
                               CryptoProObjectIdentifiers.gostR3411_94_CryptoProParamSet);
            }
            else
            {   // strictly speaking this may not be applicable...
                ECCurve curve = EC5Util.convertCurve(ecSpec.getCurve());

                X9ECParameters ecP = new X9ECParameters(
                    curve,
                    EC5Util.convertPoint(curve, ecSpec.getGenerator(), withCompression),
                    ecSpec.getOrder(),
                    BigInteger.valueOf(ecSpec.getCofactor()),
                    ecSpec.getCurve().getSeed());

                params = new X962Parameters(ecP);
            }
        }

        BigInteger bX = this.q.getX().toBigInteger();
        BigInteger bY = this.q.getY().toBigInteger();
        byte[] encKey = new byte[64];

        extractBytes(encKey, 0, bX);
        extractBytes(encKey, 32, bY);

        return ProviderUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001, params), new DEROctetString(encKey));
    }

    private void extractBytes(byte[] encKey, int offSet, BigInteger bI)
    {
        byte[] val = bI.toByteArray();
        if (val.length < 32)
        {
            byte[] tmp = new byte[32];
            System.arraycopy(val, 0, tmp, tmp.length - val.length, val.length);
            val = tmp;
        }

        for (int i = 0; i != 32; i++)
        {
            encKey[offSet + i] = val[val.length - 1 - i];
        }
    }

    public ECParameterSpec getParams()
    {
        return ecSpec;
    }

    public ECPoint getW()
    {
        return new ECPoint(q.getX().toBigInteger(), q.getY().toBigInteger());
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

    public org.bouncycastle.math.ec.ECPoint engineGetQ()
    {
        return q;
    }

    public String toString()
    {
        StringBuffer buf = new StringBuffer();
        String nl = System.getProperty("line.separator");

        buf.append("EC Public Key").append(nl);
        buf.append("            X: ").append(this.q.getX().toBigInteger().toString(16)).append(nl);
        buf.append("            Y: ").append(this.q.getY().toBigInteger().toString(16)).append(nl);

        return buf.toString();

    }
    
    public void setPointFormat(String style)
    {
       withCompression = !("UNCOMPRESSED".equalsIgnoreCase(style));
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof ECPublicKey))
        {
            return false;
        }

        ECPublicKey other = (ECPublicKey)o;

        return getW().equals(other.getW()) && getParams().equals(other.getParams());
    }

    public int hashCode()
    {
        return getW().hashCode() ^ getParams().hashCode();
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        byte[] enc = (byte[])in.readObject();

        populateFromPubKeyInfo(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(enc)));

        this.algorithm = (String)in.readObject();
        this.withCompression = in.readBoolean();
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.writeObject(this.getEncoded());
        out.writeObject(algorithm);
        out.writeBoolean(withCompression);
    }
}
