package org.spongycastle.jce.provider;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;

import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.params.DSAParameters;
import org.spongycastle.crypto.params.DSAPrivateKeyParameters;
import org.spongycastle.crypto.params.DSAPublicKeyParameters;

/**
 * utility class for converting jce/jca DSA objects
 * objects into their org.spongycastle.crypto counterparts.
 */
public class DSAUtil
{
    static public AsymmetricKeyParameter generatePublicKeyParameter(
        PublicKey    key)
        throws InvalidKeyException
    {
        if (key instanceof DSAPublicKey)
        {
            DSAPublicKey    k = (DSAPublicKey)key;

            return new DSAPublicKeyParameters(k.getY(),
                new DSAParameters(k.getParams().getP(), k.getParams().getQ(), k.getParams().getG()));
        }

        throw new InvalidKeyException("can't identify DSA public key: " + key.getClass().getName());
    }

    static public AsymmetricKeyParameter generatePrivateKeyParameter(
        PrivateKey    key)
        throws InvalidKeyException
    {
        if (key instanceof DSAPrivateKey)
        {
            DSAPrivateKey    k = (DSAPrivateKey)key;

            return new DSAPrivateKeyParameters(k.getX(),
                new DSAParameters(k.getParams().getP(), k.getParams().getQ(), k.getParams().getG()));
        }
                        
        throw new InvalidKeyException("can't identify DSA private key.");
    }
}
