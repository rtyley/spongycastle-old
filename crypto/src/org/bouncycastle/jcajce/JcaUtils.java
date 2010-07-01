package org.bouncycastle.jcajce;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Hashtable;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

public class JcaUtils
{
    //
    // key types
    //
    private static Hashtable keyAlgorithms = new Hashtable();

    static
    {
        keyAlgorithms.put(PKCSObjectIdentifiers.rsaEncryption, "RSA");
        keyAlgorithms.put(X9ObjectIdentifiers.id_dsa, "DSA");
    }

    public static PublicKey toPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        X509EncodedKeySpec xspec = new X509EncodedKeySpec(new DERBitString(subjectPublicKeyInfo).getBytes());
        AlgorithmIdentifier keyAlg = subjectPublicKeyInfo.getAlgorithmId();

        try
        {
            try
            {
                return KeyFactory.getInstance(keyAlg.getObjectId().getId()).generatePublic(xspec);
            }
            catch (NoSuchAlgorithmException e)
            {
                //
                // try an alternate
                //
                if (keyAlgorithms.get(keyAlg.getObjectId()) != null)
                {
                    String  keyAlgorithm = (String)keyAlgorithms.get(keyAlg.getObjectId());

                    return KeyFactory.getInstance(keyAlgorithm).generatePublic(xspec);
                }

                throw e;
            }
        }
        catch (InvalidKeySpecException e)
        {
            throw new InvalidKeyException("error decoding public key", e);
        }
    }

    public static PublicKey toPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo, String provider)
        throws NoSuchAlgorithmException, NoSuchProviderException,
                InvalidKeyException
    {
        Provider prov = Security.getProvider(provider);

        if (prov != null)
        {
            return toPublicKey(subjectPublicKeyInfo, prov);
        }

        throw new NoSuchProviderException("cannot find provider: " + provider);
    }

    public static PublicKey toPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo, Provider provider)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        X509EncodedKeySpec xspec = new X509EncodedKeySpec(new DERBitString(subjectPublicKeyInfo).getBytes());
        AlgorithmIdentifier keyAlg = subjectPublicKeyInfo.getAlgorithmId();

        try
        {
            try
            {
                return KeyFactory.getInstance(keyAlg.getObjectId().getId(), provider).generatePublic(xspec);
            }
            catch (NoSuchAlgorithmException e)
            {
                //
                // try an alternate
                //
                if (keyAlgorithms.get(keyAlg.getObjectId()) != null)
                {
                    String  keyAlgorithm = (String)keyAlgorithms.get(keyAlg.getObjectId());

                    return KeyFactory.getInstance(keyAlgorithm, provider).generatePublic(xspec);
                }

                throw e;
            }
        }
        catch (InvalidKeySpecException e)
        {
            throw new InvalidKeyException("error decoding public key", e);
        }
    }
}