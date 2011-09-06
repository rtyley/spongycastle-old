package org.bouncycastle.jcajce.provider.asymmetric.dsa;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;

public class KeyFactorySpi
    extends BaseKeyFactorySpi
{
    public KeyFactorySpi()
    {
    }

    protected KeySpec engineGetKeySpec(
        Key key,
        Class spec)
        throws InvalidKeySpecException
    {
        if (spec.isAssignableFrom(DSAPublicKeySpec.class) && key instanceof DSAPublicKey)
        {
            DSAPublicKey k = (DSAPublicKey)key;

            return new DSAPublicKeySpec(k.getY(), k.getParams().getP(), k.getParams().getQ(), k.getParams().getG());
        }
        else if (spec.isAssignableFrom(DSAPrivateKeySpec.class) && key instanceof java.security.interfaces.DSAPrivateKey)
        {
            java.security.interfaces.DSAPrivateKey k = (java.security.interfaces.DSAPrivateKey)key;

            return new DSAPrivateKeySpec(k.getX(), k.getParams().getP(), k.getParams().getQ(), k.getParams().getG());
        }

        return super.engineGetKeySpec(key, spec);
    }

    protected Key engineTranslateKey(
        Key key)
        throws InvalidKeyException
    {
        if (key instanceof DSAPublicKey)
        {
            return new BCDSAPublicKey((DSAPublicKey)key);
        }
        else if (key instanceof DSAPrivateKey)
        {
            return new BCDSAPrivateKey((DSAPrivateKey)key);
        }

        throw new InvalidKeyException("key type unknown");
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        ASN1ObjectIdentifier algOid = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();

        if (DSAUtil.isDsaOid(algOid))
        {
            return new BCDSAPrivateKey(keyInfo);
        }
        else
        {
            throw new IOException("algorithm identifier " + algOid + " in key not recognised");
        }
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        ASN1ObjectIdentifier algOid = keyInfo.getAlgorithm().getAlgorithm();

        if (DSAUtil.isDsaOid(algOid))
        {
            return new BCDSAPublicKey(keyInfo);
        }
        else
        {
            throw new IOException("algorithm identifier " + algOid + " in key not recognised");
        }
    }
    /**
     * create a public key from the given DER encoded input stream. 
     */
    public static PublicKey createPublicKeyFromDERStream(
        byte[] in)
        throws IOException
    {
        return createPublicKeyFromPublicKeyInfo(
            SubjectPublicKeyInfo.getInstance(in));
    }

    /**
     * create a public key from the given public key info object.
     */
    static PublicKey createPublicKeyFromPublicKeyInfo(
        SubjectPublicKeyInfo info)
    {
        ASN1ObjectIdentifier algOid = info.getAlgorithm().getAlgorithm();

        if (algOid.equals(X9ObjectIdentifiers.id_dsa))
        {
            return new BCDSAPublicKey(info);
        }
        else if (algOid.equals(OIWObjectIdentifiers.dsaWithSHA1))
        {
            return new BCDSAPublicKey(info);
        }

        return null;
    }

    /**
     * create a private key from the given DER encoded input stream. 
     */
    protected static PrivateKey createPrivateKeyFromDERStream(
        byte[] in)
        throws IOException
    {
        return createPrivateKeyFromPrivateKeyInfo(
            PrivateKeyInfo.getInstance(in));
    }

    /**
     * create a private key from the given public key info object.
     */
    static PrivateKey createPrivateKeyFromPrivateKeyInfo(
        PrivateKeyInfo info)
        throws IOException
    {
        ASN1ObjectIdentifier algOid = info.getPrivateKeyAlgorithm().getAlgorithm();

        if (algOid.equals(X9ObjectIdentifiers.id_dsa))
        {
            return new BCDSAPrivateKey(info);
        }
        else if (algOid.equals(OIWObjectIdentifiers.dsaWithSHA1))
        {
            return new BCDSAPrivateKey(info);
        }
        else
        {
            throw new RuntimeException("algorithm identifier " + algOid + " in key not recognised");
        }
    }

    protected PrivateKey engineGeneratePrivate(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof DSAPrivateKeySpec)
        {
            return new BCDSAPrivateKey((DSAPrivateKeySpec)keySpec);
        }
        else if (keySpec instanceof PKCS8EncodedKeySpec)
        {
            try
            {
                return KeyFactorySpi.createPrivateKeyFromDERStream(
                    ((PKCS8EncodedKeySpec)keySpec).getEncoded());
            }
            catch (IOException e)
            {
                throw new InvalidKeySpecException("unable to decode PKCS8 bytes: " + e.getMessage(), e);
            }
        }

        throw new InvalidKeySpecException("unknown keySpec: " + keySpec);
    }

    protected PublicKey engineGeneratePublic(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof DSAPublicKeySpec)
        {
            return new BCDSAPublicKey((DSAPublicKeySpec)keySpec);
        }
        else if (keySpec instanceof X509EncodedKeySpec)
        {
            try
            {
                return createPublicKeyFromDERStream(
                    ((X509EncodedKeySpec)keySpec).getEncoded());
            }
            catch (Exception e)
            {
                throw new InvalidKeySpecException(e.toString());
            }
        }

        throw new InvalidKeySpecException("unknown keySpec: " + keySpec);
    }
}
