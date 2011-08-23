package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.spec.RSAPrivateKeySpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.RSAKeyParameters;

public class BCRSAPrivateKey
    implements java.security.interfaces.RSAPrivateKey
{
    static final long serialVersionUID = 5110188922551353628L;

    private static BigInteger ZERO = BigInteger.valueOf(0);

    protected BigInteger modulus;
    protected BigInteger privateExponent;

    protected BCRSAPrivateKey()
    {
    }

    BCRSAPrivateKey(
        RSAKeyParameters key)
    {
        this.modulus = key.getModulus();
        this.privateExponent = key.getExponent();
    }

    BCRSAPrivateKey(
        RSAPrivateKeySpec spec)
    {
        this.modulus = spec.getModulus();
        this.privateExponent = spec.getPrivateExponent();
    }

    BCRSAPrivateKey(
        java.security.interfaces.RSAPrivateKey key)
    {
        this.modulus = key.getModulus();
        this.privateExponent = key.getPrivateExponent();
    }

    public BigInteger getModulus()
    {
        return modulus;
    }

    public BigInteger getPrivateExponent()
    {
        return privateExponent;
    }

    public String getAlgorithm()
    {
        return "RSA";
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public byte[] getEncoded()
    {
        try
        {
            PrivateKeyInfo info = new PrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, new DERNull()), new RSAPrivateKey(getModulus(), ZERO, getPrivateExponent(), ZERO, ZERO, ZERO, ZERO, ZERO).toASN1Primitive());

            return info.getEncoded(ASN1Encoding.DER);
        }
        catch (Exception e)
        {
            return null;
        }
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof java.security.interfaces.RSAPrivateKey))
        {
            return false;
        }

        if (o == this)
        {
            return true;
        }

        java.security.interfaces.RSAPrivateKey key = (java.security.interfaces.RSAPrivateKey)o;

        return getModulus().equals(key.getModulus())
            && getPrivateExponent().equals(key.getPrivateExponent());
    }

    public int hashCode()
    {
        return getModulus().hashCode() ^ getPrivateExponent().hashCode();
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        this.modulus = (BigInteger)in.readObject();
        this.privateExponent = (BigInteger)in.readObject();
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.writeObject(modulus);
        out.writeObject(privateExponent);
    }
}
