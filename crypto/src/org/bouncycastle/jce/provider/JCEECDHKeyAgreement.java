package org.bouncycastle.jce.provider;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Hashtable;

/**
 * Diffie-Hellman key agreement using elliptic curve keys, ala IEEE P1363
 * both the simple one, and the simple one with cofactors are supported.
 */
public class JCEECDHKeyAgreement
    extends KeyAgreementSpi
{
    private static final Hashtable algorithms = new Hashtable();

    static
    {
        Integer i128 = new Integer(128);
        Integer i192 = new Integer(192);
        Integer i256 = new Integer(256);

        algorithms.put(NISTObjectIdentifiers.id_aes128_CBC.getId(), i128);
        algorithms.put(NISTObjectIdentifiers.id_aes192_CBC.getId(), i192);
        algorithms.put(NISTObjectIdentifiers.id_aes256_CBC.getId(), i256);
        algorithms.put(NISTObjectIdentifiers.id_aes128_wrap.getId(), i128);
        algorithms.put(NISTObjectIdentifiers.id_aes192_wrap.getId(), i192);
        algorithms.put(NISTObjectIdentifiers.id_aes256_wrap.getId(), i256);
    }

    private BigInteger          result;
    private CipherParameters    privKey;
    private BasicAgreement      agreement;
    private DerivationFunction  kdf;

    private byte[] bigIntToBytes(
        BigInteger    r)
    {
        byte[]    tmp = r.toByteArray();
        
        if (tmp[0] == 0)
        {
            byte[]    ntmp = new byte[tmp.length - 1];
            
            System.arraycopy(tmp, 1, ntmp, 0, ntmp.length);
            return ntmp;
        }
        
        return tmp;
    }
    
    protected JCEECDHKeyAgreement(
        BasicAgreement  agreement)
    {
        this.agreement = agreement;
    }

    protected JCEECDHKeyAgreement(
        BasicAgreement  agreement,
        DerivationFunction kdf)
    {
        this.agreement = agreement;
        this.kdf = kdf;
    }

    protected Key engineDoPhase(
        Key     key,
        boolean lastPhase) 
        throws InvalidKeyException, IllegalStateException
    {
        if (privKey == null)
        {
            throw new IllegalStateException("EC Diffie-Hellman not initialised.");
        }

        if (!lastPhase)
        {
            throw new IllegalStateException("EC Diffie-Hellman can only be between two parties.");
        }

        if (!(key instanceof ECPublicKey))
        {
            throw new InvalidKeyException("EC Key Agreement doPhase requires ECPublicKey");
        }

        CipherParameters pubKey = ECUtil.generatePublicKeyParameter((PublicKey)key);

        result = agreement.calculateAgreement(pubKey);

        return null;
    }

    protected byte[] engineGenerateSecret() 
        throws IllegalStateException
    {
        return bigIntToBytes(result);
    }

    protected int engineGenerateSecret(
        byte[]  sharedSecret,
        int     offset) 
        throws IllegalStateException, ShortBufferException
    {
        byte[]  secret = bigIntToBytes(result);

        if (sharedSecret.length - offset < secret.length)
        {
            throw new ShortBufferException("ECKeyAgreement - buffer too short");
        }

        if (kdf != null)
        {
            kdf.init(new KDFParameters(secret, null));
            kdf.generateBytes(sharedSecret, offset, sharedSecret.length - offset);
        }
        else
        {
            System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
        }
        
        return secret.length;
    }

    protected SecretKey engineGenerateSecret(
        String algorithm) 
    {
        if (algorithms.containsKey(algorithm))
        {
            int    keySize = ((Integer)algorithms.get(algorithm)).intValue();

            byte[] keyBytes = new byte[keySize / 8];

            if (kdf != null)
            {
                kdf.init(new KDFParameters(bigIntToBytes(result), null));
                kdf.generateBytes(keyBytes, 0, keyBytes.length);
            }
            else
            {
                System.arraycopy(bigIntToBytes(result), 0, keyBytes, 0, keyBytes.length);
            }

            return new SecretKeySpec(keyBytes, algorithm);
        }

        return new SecretKeySpec(bigIntToBytes(result), algorithm);
    }

    protected void engineInit(
        Key                     key,
        AlgorithmParameterSpec  params,
        SecureRandom            random) 
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (!(key instanceof ECPrivateKey))
        {
            throw new InvalidKeyException("ECKeyAgreement requires ECPrivateKey for initialisation");
        }

        privKey = ECUtil.generatePrivateKeyParameter((PrivateKey)key);

        agreement.init(privKey);
    }

    protected void engineInit(
        Key             key,
        SecureRandom    random) 
        throws InvalidKeyException
    {
        if (!(key instanceof ECPrivateKey))
        {
            throw new InvalidKeyException("ECKeyAgreement requires ECPrivateKey");
        }

        privKey = ECUtil.generatePrivateKeyParameter((PrivateKey)key);

        agreement.init(privKey);
    }

    public static class DH
        extends JCEECDHKeyAgreement
    {
        public DH()
        {
            super(new ECDHBasicAgreement());
        }
    }

    public static class DHC
        extends JCEECDHKeyAgreement
    {
        public DHC()
        {
            super(new ECDHCBasicAgreement());
        }
    }

    public static class DHwithSHA1KDF
        extends JCEECDHKeyAgreement
    {
        public DHwithSHA1KDF()
        {
            super(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()));
        }
    }
}
