package org.bouncycastle.jce.provider.asymmetric.ec;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.agreement.kdf.DHKDFParameters;
import org.bouncycastle.crypto.agreement.kdf.ECDHKEKGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.asymmetric.ec.ECUtil;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Hashtable;

/**
 * Diffie-Hellman key agreement using elliptic curve keys, ala IEEE P1363
 * both the simple one, and the simple one with cofactors are supported.
 */
public class KeyAgreement
    extends KeyAgreementSpi
{
    private static final X9IntegerConverter converter = new X9IntegerConverter();
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
        algorithms.put(PKCSObjectIdentifiers.id_alg_CMS3DESwrap.getId(), i192);
    }

    private BigInteger             result;
    private ECPrivateKeyParameters privKey;
    private BasicAgreement         agreement;
    private DerivationFunction     kdf;

    private byte[] bigIntToBytes(
        BigInteger    r)
    {
        return converter.integerToBytes(r, converter.getByteLength(privKey.getParameters().getG().getX()));
    }
    
    protected KeyAgreement(
        BasicAgreement  agreement)
    {
        this.agreement = agreement;
    }

    protected KeyAgreement(
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

        System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
        
        return secret.length;
    }

    protected SecretKey engineGenerateSecret(
        String algorithm)
        throws NoSuchAlgorithmException
    {
        if (kdf != null)
        {
            if (!algorithms.containsKey(algorithm))
            {
                throw new NoSuchAlgorithmException("unknown algorithm encountered: " + algorithm);
            }
            
            int    keySize = ((Integer)algorithms.get(algorithm)).intValue();

            DHKDFParameters params = new DHKDFParameters(new DERObjectIdentifier(algorithm), keySize, bigIntToBytes(result));

            byte[] keyBytes = new byte[keySize / 8];

            kdf.init(params);
            
            kdf.generateBytes(keyBytes, 0, keyBytes.length);

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

        privKey = (ECPrivateKeyParameters)ECUtil.generatePrivateKeyParameter((PrivateKey)key);

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

        privKey = (ECPrivateKeyParameters)ECUtil.generatePrivateKeyParameter((PrivateKey)key);

        agreement.init(privKey);
    }

    public static class DH
        extends KeyAgreement
    {
        public DH()
        {
            super(new ECDHBasicAgreement());
        }
    }

    public static class DHC
        extends KeyAgreement
    {
        public DHC()
        {
            super(new ECDHCBasicAgreement());
        }
    }

    public static class DHwithSHA1KDF
        extends KeyAgreement
    {
        public DHwithSHA1KDF()
        {
            super(new ECDHBasicAgreement(), new ECDHKEKGenerator(new SHA1Digest()));
        }
    }
}
