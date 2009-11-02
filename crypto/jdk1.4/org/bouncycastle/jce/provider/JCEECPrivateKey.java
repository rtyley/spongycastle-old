package org.bouncycastle.jce.provider;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKeyStructure;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.jce.interfaces.ECPointEncoder;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.jce.provider.asymmetric.ec.ECUtil;

public class JCEECPrivateKey
    implements ECPrivateKey, PKCS12BagAttributeCarrier, ECPointEncoder
{
    private String          algorithm = "EC";
    private BigInteger      d;
    private ECParameterSpec ecSpec;
    private boolean         withCompression;

    private DERBitString publicKey;

    private PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();

    protected JCEECPrivateKey()
    {
    }

    JCEECPrivateKey(
        ECPrivateKey    key)
    {
        this.d = key.getD();
        this.algorithm = key.getAlgorithm();
        this.ecSpec = key.getParameters();
    }

    public JCEECPrivateKey(
        String              algorithm,
        ECPrivateKeySpec    spec)
    {
        this.algorithm = algorithm;
        this.d = spec.getD();
        this.ecSpec = spec.getParams();
    }

    public JCEECPrivateKey(
        String                  algorithm,
        ECPrivateKeyParameters  params,
        JCEECPublicKey          pubKey,
        ECParameterSpec         spec)
    {
        ECDomainParameters      dp = params.getParameters();

        this.algorithm = algorithm;
        this.d = params.getD();

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

        publicKey = getPublicKeyDetails(pubKey);
    }

    public JCEECPrivateKey(
        String                  algorithm,
        ECPrivateKeyParameters  params)
    {
        this.algorithm = algorithm;
        this.d = params.getD();
        this.ecSpec = null;
    }

    public JCEECPrivateKey(
        String             algorithm,
        JCEECPrivateKey    key)
    {
        this.algorithm = algorithm;
        this.d = key.d;
        this.ecSpec = key.ecSpec;
        this.withCompression = key.withCompression;
        this.publicKey = key.publicKey;
        this.attrCarrier = key.attrCarrier;
    }

    JCEECPrivateKey(
        PrivateKeyInfo      info)
    {
        populateFromPrivKeyInfo(info);
    }

    private void populateFromPrivKeyInfo(PrivateKeyInfo info)
    {
        X962Parameters      params = new X962Parameters((DERObject)info.getAlgorithmId().getParameters());

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
        }
        else if (params.isImplicitlyCA())
        {
            ecSpec = null;
        }
        else
        {
            X9ECParameters          ecP = new X9ECParameters((ASN1Sequence)params.getParameters());
            ecSpec = new ECParameterSpec(ecP.getCurve(),
                                            ecP.getG(),
                                            ecP.getN(),
                                            ecP.getH(),
                                            ecP.getSeed());
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
            this.publicKey = ec.getPublicKey();
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
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        DEROutputStream         dOut = new DEROutputStream(bOut);
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
                generator = new ECPoint.Fp(curve, p.getG().getX(), p.getG().getY(), withCompression);
            } 
            else if (curve instanceof ECCurve.F2m) 
            {
                generator = new ECPoint.F2m(curve, p.getG().getX(), p.getG().getY(), withCompression);
            }
            else 
            {
                throw new UnsupportedOperationException("Subclass of ECPoint " + curve.getClass().toString() + "not supported");
            }
            
            X9ECParameters ecP = new X9ECParameters(
                  p.getCurve(),
                  generator,
                  p.getN(),
                  p.getH(),
                  p.getSeed());

            params = new X962Parameters(ecP);
        }

        PrivateKeyInfo        info;
        ECPrivateKeyStructure keyStructure;

        if (publicKey != null)
        {
            keyStructure = new ECPrivateKeyStructure(this.getD(), publicKey, params);
        }
        else
        {
            keyStructure = new ECPrivateKeyStructure(this.getD(), params);
        }

        if (algorithm.equals("ECGOST3410"))
        {
            info = new PrivateKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001, params.getDERObject()), keyStructure.getDERObject());
        }
        else
        {
            info = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params.getDERObject()), keyStructure.getDERObject());
        }
        
        try
        {
            dOut.writeObject(info);
            dOut.close();
        }
        catch (IOException e)
        {
            throw new RuntimeException("Error encoding EC private key");
        }

        return bOut.toByteArray();
    }

    public ECParameterSpec getParams()
    {
        return (ECParameterSpec)ecSpec;
    }

    public ECParameterSpec getParameters()
    {
        return (ECParameterSpec)ecSpec;
    }
    
    public BigInteger getD()
    {
        return d;
    }

    public void setBagAttribute(
        DERObjectIdentifier oid,
        DEREncodable        attribute)
    {
        attrCarrier.setBagAttribute(oid, attribute);
    }

    public DEREncodable getBagAttribute(
        DERObjectIdentifier oid)
    {
        return attrCarrier.getBagAttribute(oid);
    }

    public Enumeration getBagAttributeKeys()
    {
        return attrCarrier.getBagAttributeKeys();
    }
    
    public void setPointFormat(String style)
    {
       withCompression = !("UNCOMPRESSED".equalsIgnoreCase(style));
    }

    ECParameterSpec engineGetSpec()
    {
        if (ecSpec != null)
        {
            return ecSpec;
        }

        return ProviderUtil.getEcImplicitlyCa();
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof JCEECPrivateKey))
        {
            return false;
        }

        JCEECPrivateKey other = (JCEECPrivateKey)o;

        return getD().equals(other.getD()) && (engineGetSpec().equals(other.engineGetSpec()));
    }

    public int hashCode()
    {
        return getD().hashCode() ^ engineGetSpec().hashCode();
    }

    private DERBitString getPublicKeyDetails(JCEECPublicKey   pub)
    {
        try
        {
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(ASN1Object.fromByteArray(pub.getEncoded()));

            return info.getPublicKeyData();
        }
        catch (IOException e)
        {   // should never happen
            return null;
        }
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        byte[] enc = (byte[])in.readObject();

        populateFromPrivKeyInfo(PrivateKeyInfo.getInstance(ASN1Object.fromByteArray(enc)));

        this.algorithm = (String)in.readObject();
        this.withCompression = in.readBoolean();
        this.attrCarrier = new PKCS12BagAttributeCarrierImpl();

        attrCarrier.readObject(in);
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.writeObject(this.getEncoded());
        out.writeObject(algorithm);
        out.writeBoolean(withCompression);

        attrCarrier.writeObject(out);
    }
}
