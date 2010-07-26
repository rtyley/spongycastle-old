package org.bouncycastle.jce.provider.asymmetric.ec;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.jce.provider.JCEECPrivateKey;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.jce.provider.JDKKeyFactory;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

public class KeyFactory
    extends JDKKeyFactory
{
    String algorithm;

    KeyFactory(
        String algorithm)
    {
        this.algorithm = algorithm;
    }

    protected PrivateKey engineGeneratePrivate(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof PKCS8EncodedKeySpec)
        {
            try
            {
                JCEECPrivateKey key = (JCEECPrivateKey)JDKKeyFactory.createPrivateKeyFromDERStream(
                    ((PKCS8EncodedKeySpec)keySpec).getEncoded());

                return new JCEECPrivateKey(algorithm, key);
            }
            catch (Exception e)
            {
                throw new InvalidKeySpecException(e.toString());
            }
        }
        else if (keySpec instanceof ECPrivateKeySpec)
        {
            return new JCEECPrivateKey(algorithm, (ECPrivateKeySpec)keySpec);
        }

        throw new InvalidKeySpecException("Unknown KeySpec type: " + keySpec.getClass().getName());
    }

    protected PublicKey engineGeneratePublic(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof X509EncodedKeySpec)
        {
            try
            {
                JCEECPublicKey key = (JCEECPublicKey)JDKKeyFactory.createPublicKeyFromDERStream(
                    ((X509EncodedKeySpec)keySpec).getEncoded());

                return new JCEECPublicKey(algorithm, key);
            }
            catch (Exception e)
            {
                throw new InvalidKeySpecException(e.toString());
            }
        }
        else if (keySpec instanceof ECPublicKeySpec)
        {
            return new JCEECPublicKey(algorithm, (ECPublicKeySpec)keySpec);
        }

        throw new InvalidKeySpecException("Unknown KeySpec type: " + keySpec.getClass().getName());
    }

    public static class EC
        extends KeyFactory
    {
        public EC()
        {
            super("EC");
        }
    }

    public static class ECDSA
        extends KeyFactory
    {
        public ECDSA()
        {
            super("ECDSA");
        }
    }

    public static class ECGOST3410
        extends KeyFactory
    {
        public ECGOST3410()
        {
            super("ECGOST3410");
        }
    }

    public static class ECDH
        extends KeyFactory
    {
        public ECDH()
        {
            super("ECDH");
        }
    }

    public static class ECDHC
        extends KeyFactory
    {
        public ECDHC()
        {
            super("ECDHC");
        }
    }

    public static class ECMQV
        extends KeyFactory
    {
        public ECMQV()
        {
            super("ECMQV");
        }
    }
}
