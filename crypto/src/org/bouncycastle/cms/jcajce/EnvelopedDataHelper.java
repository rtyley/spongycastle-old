package org.bouncycastle.cms.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;

import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;

abstract class EnvelopedDataHelper
{
    protected static final Map BASE_CIPHER_NAMES = new HashMap();
    protected static final Map CIPHER_ALG_NAMES = new HashMap();
    protected static final Map MAC_ALG_NAMES = new HashMap();

    static
    {
        BASE_CIPHER_NAMES.put(CMSAlgorithm.DES_EDE3_CBC,  "DESEDE");
        BASE_CIPHER_NAMES.put(CMSAlgorithm.AES128_CBC,  "AES");
        BASE_CIPHER_NAMES.put(CMSAlgorithm.AES192_CBC,  "AES");
        BASE_CIPHER_NAMES.put(CMSAlgorithm.AES256_CBC,  "AES");

        CIPHER_ALG_NAMES.put(CMSAlgorithm.DES_EDE3_CBC,  "DESEDE/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(CMSAlgorithm.AES128_CBC,  "AES/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(CMSAlgorithm.AES192_CBC,  "AES/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(CMSAlgorithm.AES256_CBC,  "AES/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(new ASN1ObjectIdentifier(PKCSObjectIdentifiers.rsaEncryption.getId()), "RSA/ECB/PKCS1Padding");

        MAC_ALG_NAMES.put(CMSAlgorithm.DES_EDE3_CBC,  "DESEDEMac");
        MAC_ALG_NAMES.put(CMSAlgorithm.AES128_CBC,  "AESMac");
        MAC_ALG_NAMES.put(CMSAlgorithm.AES192_CBC,  "AESMac");
        MAC_ALG_NAMES.put(CMSAlgorithm.AES256_CBC,  "AESMac");
    }

    private SecretKey           encKey;
    private AlgorithmIdentifier algorithmIdentifier;
    private Cipher              cipher;

    Cipher createCipher(ASN1ObjectIdentifier algorithm)
        throws CMSException
    {
        try
        {
            String cipherName = (String)CIPHER_ALG_NAMES.get(algorithm);

            if (cipherName != null)
            {
                try
                {
                    // this is reversed as the Sun policy files now allow unlimited strength RSA
                    return createCipher(cipherName);
                }
                catch (NoSuchAlgorithmException e)
                {
                    // Ignore
                }
            }
            return createCipher(algorithm.getId());
        }
        catch (GeneralSecurityException e)
        {
            throw new CMSException("cannot create cipher: " + e.getMessage(), e);
        }
    }

    Mac createMac(ASN1ObjectIdentifier algorithm)
        throws CMSException
    {
        try
        {
            String macName = (String)MAC_ALG_NAMES.get(algorithm);

            if (macName != null)
            {
                try
                {
                    // this is reversed as the Sun policy files now allow unlimited strength RSA
                    return createMac(macName);
                }
                catch (NoSuchAlgorithmException e)
                {
                    // Ignore
                }
            }
            return createMac(algorithm.getId());
        }
        catch (GeneralSecurityException e)
        {
            throw new CMSException("cannot create cipher: " + e.getMessage(), e);
        }
    }

    Cipher createRFC3211Wrapper(ASN1ObjectIdentifier algorithm)
        throws CMSException
    {
        String cipherName = (String)BASE_CIPHER_NAMES.get(algorithm);

        if (cipherName == null)
        {
            throw new CMSException("no name for " + algorithm);
        }

        cipherName += "RFC3211Wrap";

        try
        {
             return createCipher(cipherName);
        }
        catch (GeneralSecurityException e)
        {
            throw new CMSException("cannot create cipher: " + e.getMessage(), e);
        }
    }

    KeyAgreement createKeyAgreement(ASN1ObjectIdentifier algorithm)
        throws CMSException
    {
        try
        {
            String agreementName = (String)BASE_CIPHER_NAMES.get(algorithm);

            if (agreementName != null)
            {
                try
                {
                    // this is reversed as the Sun policy files now allow unlimited strength RSA
                    return createKeyAgreement(agreementName);
                }
                catch (NoSuchAlgorithmException e)
                {
                    // Ignore
                }
            }
            return createKeyAgreement(algorithm.getId());
        }
        catch (GeneralSecurityException e)
        {
            throw new CMSException("cannot create key pair generator: " + e.getMessage(), e);
        }
    }

    AlgorithmParameterGenerator createAlgorithmParameterGenerator(ASN1ObjectIdentifier algorithm)
        throws GeneralSecurityException
    {
        String algorithmName = (String)BASE_CIPHER_NAMES.get(algorithm);

        if (algorithmName != null)
        {
            try
            {
                // this is reversed as the Sun policy files now allow unlimited strength RSA
                return createAlgorithmParameterGenerator(algorithmName);
            }
            catch (NoSuchAlgorithmException e)
            {
                // Ignore
            }
        }
        return createAlgorithmParameterGenerator(algorithm.getId());
    }

    Cipher createContentCipher(final Key sKey, final AlgorithmIdentifier encryptionAlgID)
        throws CMSException
    {
        return (Cipher)execute(new JCECallback()
        {
            public Object doInJCE()
                throws CMSException, InvalidAlgorithmParameterException,
                InvalidKeyException, InvalidParameterSpecException, NoSuchAlgorithmException,
                NoSuchPaddingException, NoSuchProviderException
            {
                Cipher cipher = createCipher(encryptionAlgID.getAlgorithm());
                ASN1Object sParams = (ASN1Object)encryptionAlgID.getParameters();
                String encAlg = encryptionAlgID.getAlgorithm().getId();

                if (sParams != null && !(sParams instanceof ASN1Null))
                {
                    try
                    {
                        AlgorithmParameters params = createAlgorithmParameters(encryptionAlgID.getAlgorithm());

                        try
                        {
                            params.init(sParams.getEncoded(), "ASN.1");
                        }
                        catch (IOException e)
                        {
                            throw new CMSException("error decoding algorithm parameters.", e);
                        }

                        cipher.init(Cipher.DECRYPT_MODE, sKey, params);
                    }
                    catch (NoSuchAlgorithmException e)
                    {
                        if (encAlg.equals(CMSEnvelopedDataGenerator.DES_EDE3_CBC)
                            || encAlg.equals(CMSEnvelopedDataGenerator.IDEA_CBC)
                            || encAlg.equals(CMSEnvelopedDataGenerator.AES128_CBC)
                            || encAlg.equals(CMSEnvelopedDataGenerator.AES192_CBC)
                            || encAlg.equals(CMSEnvelopedDataGenerator.AES256_CBC))
                        {
                            cipher.init(Cipher.DECRYPT_MODE, sKey, new IvParameterSpec(
                                ASN1OctetString.getInstance(sParams).getOctets()));
                        }
                        else
                        {
                            throw e;
                        }
                    }
                }
                else
                {
                    if (encAlg.equals(CMSEnvelopedDataGenerator.DES_EDE3_CBC)
                        || encAlg.equals(CMSEnvelopedDataGenerator.IDEA_CBC)
                        || encAlg.equals(CMSEnvelopedDataGenerator.CAST5_CBC))
                    {
                        cipher.init(Cipher.DECRYPT_MODE, sKey, new IvParameterSpec(new byte[8]));
                    }
                    else
                    {
                        cipher.init(Cipher.DECRYPT_MODE, sKey);
                    }
                }

                return cipher;
            }
        });
    }

    Mac createContentMac(final Key sKey, final AlgorithmIdentifier macAlgId)
        throws CMSException
    {
        return (Mac)execute(new JCECallback()
        {
            public Object doInJCE()
                throws CMSException, InvalidAlgorithmParameterException,
                InvalidKeyException, InvalidParameterSpecException, NoSuchAlgorithmException,
                NoSuchPaddingException, NoSuchProviderException
            {
                Mac mac = createMac(macAlgId.getAlgorithm());
                ASN1Object sParams = (ASN1Object)macAlgId.getParameters();
                String macAlg = macAlgId.getAlgorithm().getId();

                if (sParams != null && !(sParams instanceof ASN1Null))
                {
                    try
                    {
                        AlgorithmParameters params = createAlgorithmParameters(macAlgId.getAlgorithm());

                        try
                        {
                            params.init(sParams.getEncoded(), "ASN.1");
                        }
                        catch (IOException e)
                        {
                            throw new CMSException("error decoding algorithm parameters.", e);
                        }

                        mac.init(sKey, params.getParameterSpec(IvParameterSpec.class));
                    }
                    catch (NoSuchAlgorithmException e)
                    {
                        throw e;
                    }
                }
                else
                {
                    mac.init(sKey);
                }

                return mac;
            }
        });
    }

    AlgorithmParameters createAlgorithmParameters(ASN1ObjectIdentifier algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        String algorithmName = (String)BASE_CIPHER_NAMES.get(algorithm);

        if (algorithmName != null)
        {
            try
            {
                // this is reversed as the Sun policy files now allow unlimited strength RSA
                return createAlgorithmParameters(algorithmName);
            }
            catch (NoSuchAlgorithmException e)
            {
                // Ignore
            }
        }
        return createAlgorithmParameters(algorithm.getId());
    }


    KeyPairGenerator createKeyPairGenerator(DERObjectIdentifier algorithm)
        throws CMSException
    {
        try
        {
            String cipherName = (String)BASE_CIPHER_NAMES.get(algorithm);

            if (cipherName != null)
            {
                try
                {
                    // this is reversed as the Sun policy files now allow unlimited strength RSA
                    return createKeyPairGenerator(cipherName);
                }
                catch (NoSuchAlgorithmException e)
                {
                    // Ignore
                }
            }
            return createKeyPairGenerator(algorithm.getId());
        }
        catch (GeneralSecurityException e)
        {
            throw new CMSException("cannot create key pair generator: " + e.getMessage(), e);
        }
    }

    public KeyGenerator createKeyGenerator(ASN1ObjectIdentifier algorithm)
        throws CMSException
    {
        try
        {
            String cipherName = (String)BASE_CIPHER_NAMES.get(algorithm);

            if (cipherName != null)
            {
                try
                {
                    // this is reversed as the Sun policy files now allow unlimited strength RSA
                    return createKeyGenerator(cipherName);
                }
                catch (NoSuchAlgorithmException e)
                {
                    // Ignore
                }
            }
            return createKeyGenerator(algorithm.getId());
        }
        catch (GeneralSecurityException e)
        {
            throw new CMSException("cannot create key generator: " + e.getMessage(), e);
        }
    }

    AlgorithmParameters generateParameters(ASN1ObjectIdentifier encryptionOID, SecretKey encKey, SecureRandom rand)
        throws CMSException
    {
        try
        {
            AlgorithmParameterGenerator pGen = createAlgorithmParameterGenerator(encryptionOID);

            if (encryptionOID.equals(CMSEnvelopedDataGenerator.RC2_CBC))
            {
                byte[]  iv = new byte[8];

                rand.nextBytes(iv);

                try
                {
                    pGen.init(new RC2ParameterSpec(encKey.getEncoded().length * 8, iv), rand);
                }
                catch (InvalidAlgorithmParameterException e)
                {
                    throw new CMSException("parameters generation error: " + e, e);
                }
            }

            return pGen.generateParameters();
        }
        catch (NoSuchAlgorithmException e)
        {
            return null;
        }
        catch (GeneralSecurityException e)
        {
            throw new CMSException("exception creating algorithm parameter generator: " + e, e);
        }
    }

    AlgorithmIdentifier getAlgorithmIdentifier(ASN1ObjectIdentifier encryptionOID, AlgorithmParameters params)
        throws CMSException
    {
        DEREncodable asn1Params;
        if (params != null)
        {
            try
            {
                asn1Params = ASN1Object.fromByteArray(params.getEncoded("ASN.1"));
            }
            catch (IOException e)
            {
                throw new CMSException("cannot encode parameters: " + e.getMessage(), e);
            }
        }
        else
        {
            asn1Params = DERNull.INSTANCE;
        }

        return new AlgorithmIdentifier(
            encryptionOID,
            asn1Params);
    }

    public void initForEncryption(ASN1ObjectIdentifier encryptionOID, int keySize, SecureRandom random)
        throws CMSException
    {
        KeyGenerator keyGen = createKeyGenerator(encryptionOID);

        if (random == null)
        {
            random = new SecureRandom();
        }

        if (keySize < 0)
        {
            keyGen.init(random);
        }
        else
        {
            keyGen.init(keySize, random);
        }

        cipher = createCipher(encryptionOID);
        encKey = keyGen.generateKey();
        AlgorithmParameters params = generateParameters(encryptionOID, encKey, random);

        try
        {
            cipher.init(Cipher.ENCRYPT_MODE, encKey, params, random);
        }
        catch (GeneralSecurityException e)
        {
            throw new CMSException("unable to initialize cipher: " + e.getMessage(), e);
        }

        //
        // If params are null we try and second guess on them as some providers don't provide
        // algorithm parameter generation explicity but instead generate them under the hood.
        //
        if (params == null)
        {
            params = cipher.getParameters();
        }

        algorithmIdentifier = getAlgorithmIdentifier(encryptionOID, params);
    }

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return algorithmIdentifier;
    }

    public CipherOutputStream getCipherOutputStream(OutputStream dOut)
    {
        return new CipherOutputStream(dOut, cipher);
    }

    public byte[] getEncKey()
    {
        return encKey.getEncoded();
    }

    static Object execute(JCECallback callback) throws CMSException
    {
        try
        {
            return callback.doInJCE();
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new CMSException("can't find algorithm.", e);
        }
        catch (InvalidKeyException e)
        {
            throw new CMSException("key invalid in message.", e);
        }
        catch (NoSuchProviderException e)
        {
            throw new CMSException("can't find provider.", e);
        }
        catch (NoSuchPaddingException e)
        {
            throw new CMSException("required padding not supported.", e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new CMSException("algorithm parameters invalid.", e);
        }
        catch (InvalidParameterSpecException e)
        {
            throw new CMSException("MAC algorithm parameter spec invalid.", e);
        }
    }

    public KeyFactory createKeyFactory(ASN1ObjectIdentifier algorithm)
        throws CMSException
    {
        try
        {
            String cipherName = (String)BASE_CIPHER_NAMES.get(algorithm);

            if (cipherName != null)
            {
                try
                {
                    // this is reversed as the Sun policy files now allow unlimited strength RSA
                    return createKeyFactory(cipherName);
                }
                catch (NoSuchAlgorithmException e)
                {
                    // Ignore
                }
            }
            return createKeyFactory(algorithm.getId());
        }
        catch (GeneralSecurityException e)
        {
            throw new CMSException("cannot create key factory: " + e.getMessage(), e);
        }
    }

    static interface JCECallback
    {
        Object doInJCE()
            throws CMSException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidParameterSpecException,
            NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException;
    }

    protected abstract Cipher createCipher(String algorithm)
        throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException;

    protected abstract Mac createMac(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException;

    protected abstract KeyAgreement createKeyAgreement(String algorithm)
        throws GeneralSecurityException;

    protected abstract AlgorithmParameterGenerator createAlgorithmParameterGenerator(String algorithm)
        throws GeneralSecurityException;

    protected abstract AlgorithmParameters createAlgorithmParameters(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException;

    protected abstract KeyGenerator createKeyGenerator(String algorithm)
        throws GeneralSecurityException;

    protected abstract KeyFactory createKeyFactory(String algorithm)
         throws NoSuchAlgorithmException, NoSuchProviderException;;

    protected abstract KeyPairGenerator createKeyPairGenerator(String algorithm)
        throws GeneralSecurityException;
}
