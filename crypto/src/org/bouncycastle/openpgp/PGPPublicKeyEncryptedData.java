package org.bouncycastle.openpgp;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.jce.interfaces.ElGamalKey;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.EOFException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.DigestInputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchProviderException;
import java.security.Provider;

/**
 * A public key encrypted data object.
 */
public class PGPPublicKeyEncryptedData
    extends PGPEncryptedData
{    
    PublicKeyEncSessionPacket        keyData;
    
    PGPPublicKeyEncryptedData(
        PublicKeyEncSessionPacket    keyData,
        InputStreamPacket            encData)
    {
        super(encData);
        
        this.keyData = keyData;
    }
    
    private static Cipher getKeyCipher(
        int       algorithm,
        Provider  provider)
        throws PGPException
    {
        try
        {
            switch (algorithm)
            {
            case PGPPublicKey.RSA_ENCRYPT:
            case PGPPublicKey.RSA_GENERAL:
                return Cipher.getInstance("RSA/ECB/PKCS1Padding", provider);
            case PGPPublicKey.ELGAMAL_ENCRYPT:
            case PGPPublicKey.ELGAMAL_GENERAL:
                return Cipher.getInstance("ElGamal/ECB/PKCS1Padding", provider);
            default:
                throw new PGPException("unknown asymmetric algorithm: " + algorithm);
            }
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("Exception creating cipher", e);
        }
    }
    
    private boolean confirmCheckSum(
        byte[]    sessionInfo)
    {
        int    check = 0;
        
        for (int i = 1; i != sessionInfo.length - 2; i++)
        {
            check += sessionInfo[i] & 0xff;
        }
        
        return (sessionInfo[sessionInfo.length - 2] == (byte)(check >> 8))
                    && (sessionInfo[sessionInfo.length - 1] == (byte)(check));
    }
    
    /**
     * Return the keyID for the key used to encrypt the data.
     * 
     * @return long
     */
    public long getKeyID()
    {
        return keyData.getKeyID();
    }

    /**
     * Return the algorithm code for the symmetric algorithm used to encrypt the data.
     *
     * @return integer algorithm code
     */
    public int getSymmetricAlgorithm(
        PGPPrivateKey  privKey,
        String         provider)
        throws PGPException, NoSuchProviderException
    {
        return getSymmetricAlgorithm(privKey, PGPUtil.getProvider(provider));
    }

    public int getSymmetricAlgorithm(
        PGPPrivateKey  privKey,
        Provider       provider)
        throws PGPException, NoSuchProviderException
    {
        byte[] plain = fetchSymmetricKeyData(privKey, provider);

        return plain[0];
    }

    /**
     * Return the decrypted data stream for the packet.
     *
     * @param privKey private key to use
     * @param provider provider to use for private key and symmetric key decryption.
     * @return InputStream
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    public InputStream getDataStream(
        PGPPrivateKey  privKey,
        String         provider)
        throws PGPException, NoSuchProviderException
    {
        return getDataStream(privKey, provider, provider);
    }

    public InputStream getDataStream(
        PGPPrivateKey  privKey,
        Provider       provider)
        throws PGPException
    {
        return getDataStream(privKey, provider, provider);
    }

    /**
     * Return the decrypted data stream for the packet.
     * 
     * @param privKey private key to use.
     * @param asymProvider asymetric provider to use with private key.
     * @param provider provider to use for symmetric algorithm.
     * @return InputStream
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    public InputStream getDataStream(
        PGPPrivateKey  privKey,
        String         asymProvider,
        String         provider)
        throws PGPException, NoSuchProviderException
    {
        return getDataStream(privKey, PGPUtil.getProvider(asymProvider), PGPUtil.getProvider(provider));
    }

    public InputStream getDataStream(
        PGPPrivateKey  privKey,
        Provider       asymProvider,
        Provider       provider)
        throws PGPException
    {
        byte[] plain = fetchSymmetricKeyData(privKey, asymProvider);
        
        Cipher         c2;
        
        try
        {
            if (encData instanceof SymmetricEncIntegrityPacket)
            {
                c2 =
                    Cipher.getInstance(
                        PGPUtil.getSymmetricCipherName(plain[0]) + "/CFB/NoPadding",
                            provider);
            }
            else
            {
                c2 =
                    Cipher.getInstance(
                        PGPUtil.getSymmetricCipherName(plain[0]) + "/OpenPGPCFB/NoPadding",
                        provider);
            }
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("exception creating cipher", e);
        }
        
        if (c2 != null)
        {
            try
            {
                SecretKey    key = new SecretKeySpec(plain, 1, plain.length - 3, PGPUtil.getSymmetricCipherName(plain[0]));
                
                byte[]       iv = new byte[c2.getBlockSize()];
                
                c2.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

                encStream = new BCPGInputStream(new CipherInputStream(encData.getInputStream(), c2));
                
                if (encData instanceof SymmetricEncIntegrityPacket)
                {
                    truncStream = new TruncatedStream(encStream);
                    encStream = new DigestInputStream(truncStream, MessageDigest.getInstance(PGPUtil.getDigestName(HashAlgorithmTags.SHA1), provider));
                }
                
                for (int i = 0; i != iv.length; i++)
                {
                    int    ch = encStream.read();
                    
                    if (ch < 0)
                    {
                        throw new EOFException("unexpected end of stream.");
                    }
                    
                    iv[i] = (byte)ch;
                }
                
                int    v1 = encStream.read();
                int    v2 = encStream.read();
                
                if (v1 < 0 || v2 < 0)
                {
                    throw new EOFException("unexpected end of stream.");
                }
                
                //
                // some versions of PGP appear to produce 0 for the extra
                // bytes rather than repeating the two previous bytes
                //
                /*
                 * Commented out in the light of the oracle attack.
                if (iv[iv.length - 2] != (byte)v1 && v1 != 0)
                {
                    throw new PGPDataValidationException("data check failed.");
                }
                
                if (iv[iv.length - 1] != (byte)v2 && v2 != 0)
                {
                    throw new PGPDataValidationException("data check failed.");
                }
                */
                
                return encStream;
            }
            catch (PGPException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PGPException("Exception starting decryption", e);
            }
        }
        else
        {
            return encData.getInputStream();
        }
    }

    private byte[] fetchSymmetricKeyData(PGPPrivateKey privKey, Provider asymProvider)
        throws PGPException
    {
        Cipher c1 = getKeyCipher(keyData.getAlgorithm(), asymProvider);

        try
        {
            c1.init(Cipher.DECRYPT_MODE, privKey.getKey());
        }
        catch (InvalidKeyException e)
        {
            throw new PGPException("error setting asymmetric cipher", e);
        }

        BigInteger[]    keyD = keyData.getEncSessionKey();

        if (keyData.getAlgorithm() == PGPPublicKey.RSA_ENCRYPT
            || keyData.getAlgorithm() == PGPPublicKey.RSA_GENERAL)
        {
            byte[]    bi = keyD[0].toByteArray();

            if (bi[0] == 0)
            {
                c1.update(bi, 1, bi.length - 1);
            }
            else
            {
                c1.update(bi);
            }
        }
        else
        {
            ElGamalKey k = (ElGamalKey)privKey.getKey();
            int           size = (k.getParameters().getP().bitLength() + 7) / 8;
            byte[]        tmp = new byte[size];

            byte[]        bi = keyD[0].toByteArray();
            if (bi.length > size)
            {
                c1.update(bi, 1, bi.length - 1);
            }
            else
            {
                System.arraycopy(bi, 0, tmp, tmp.length - bi.length, bi.length);
                c1.update(tmp);
            }

            bi = keyD[1].toByteArray();
            for (int i = 0; i != tmp.length; i++)
            {
                tmp[i] = 0;
            }

            if (bi.length > size)
            {
                c1.update(bi, 1, bi.length - 1);
            }
            else
            {
                System.arraycopy(bi, 0, tmp, tmp.length - bi.length, bi.length);
                c1.update(tmp);
            }
        }

        byte[] plain;
        try
        {
            plain = c1.doFinal();
        }
        catch (Exception e)
        {
            throw new PGPException("exception decrypting secret key", e);
        }

        if (!confirmCheckSum(plain))
        {
            throw new PGPKeyValidationException("key checksum failed");
        }

        return plain;
    }
}
