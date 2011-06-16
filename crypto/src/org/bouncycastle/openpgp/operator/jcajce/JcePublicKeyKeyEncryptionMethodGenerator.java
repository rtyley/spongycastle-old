package org.bouncycastle.openpgp.operator.jcajce;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import org.bouncycastle.jcajce.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.NamedJcaJceHelper;
import org.bouncycastle.jcajce.ProviderJcaJceHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PublicKeyKeyEncryptionMethodGenerator;

public class JcePublicKeyKeyEncryptionMethodGenerator
    extends PublicKeyKeyEncryptionMethodGenerator
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private SecureRandom random;
    private JcaPGPKeyConverter keyConverter = new JcaPGPKeyConverter();

    public JcePublicKeyKeyEncryptionMethodGenerator(PGPPublicKey key)
    {
        super(key);
    }

    public JcePublicKeyKeyEncryptionMethodGenerator setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

        keyConverter.setProvider(provider);

        return this;
    }

    public JcePublicKeyKeyEncryptionMethodGenerator setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

        keyConverter.setProvider(providerName);

        return this;
    }

    public JcePublicKeyKeyEncryptionMethodGenerator setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    protected byte[] encryptSessionInfo(PGPPublicKey pubKey, byte[] sessionInfo)
        throws PGPException
    {
        try
        {
            Cipher c;

            switch (pubKey.getAlgorithm())
            {
            case PGPPublicKey.RSA_ENCRYPT:
            case PGPPublicKey.RSA_GENERAL:
                c = helper.createCipher("RSA/ECB/PKCS1Padding");
                break;
            case PGPPublicKey.ELGAMAL_ENCRYPT:
            case PGPPublicKey.ELGAMAL_GENERAL:
                c = helper.createCipher("ElGamal/ECB/PKCS1Padding");
                break;
            case PGPPublicKey.DSA:
                throw new PGPException("Can't use DSA for encryption.");
            case PGPPublicKey.ECDSA:
                throw new PGPException("Can't use ECDSA for encryption.");
            default:
                throw new PGPException("unknown asymmetric algorithm: " + pubKey.getAlgorithm());
            }

            Key key = keyConverter.getPublicKey(pubKey);

            c.init(Cipher.ENCRYPT_MODE, key, random);

            return c.doFinal(sessionInfo);
        }
        catch (IllegalBlockSizeException e)
        {
            throw new PGPException("illegal block size: " + e.getMessage(), e);
        }
        catch (BadPaddingException e)
        {
            throw new PGPException("bad padding: " + e.getMessage(), e);
        }
        catch (InvalidKeyException e)
        {
            throw new PGPException("key invalid: " + e.getMessage(), e);
        }
    }
}
