package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.cms.KEKRecipientInfo;
import org.bouncycastle.asn1.cms.KeyAgreeRecipientInfo;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.PasswordRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.Mac;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.AlgorithmParameterGenerator;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

class CMSEnvelopedHelper
{
    static final CMSEnvelopedHelper INSTANCE = new CMSEnvelopedHelper();

    private static final Map KEYSIZES = new HashMap();
    private static final Map BASE_CIPHER_NAMES = new HashMap();
    private static final Map CIPHER_ALG_NAMES = new HashMap();
    private static final Map MAC_ALG_NAMES = new HashMap();

    static
    {
        KEYSIZES.put(CMSEnvelopedGenerator.DES_EDE3_CBC,  new Integer(192));
        KEYSIZES.put(CMSEnvelopedGenerator.AES128_CBC,  new Integer(128));
        KEYSIZES.put(CMSEnvelopedGenerator.AES192_CBC,  new Integer(192));
        KEYSIZES.put(CMSEnvelopedGenerator.AES256_CBC,  new Integer(256));

        BASE_CIPHER_NAMES.put(CMSEnvelopedGenerator.DES_EDE3_CBC,  "DESEDE");
        BASE_CIPHER_NAMES.put(CMSEnvelopedGenerator.AES128_CBC,  "AES");
        BASE_CIPHER_NAMES.put(CMSEnvelopedGenerator.AES192_CBC,  "AES");
        BASE_CIPHER_NAMES.put(CMSEnvelopedGenerator.AES256_CBC,  "AES");

        CIPHER_ALG_NAMES.put(CMSEnvelopedGenerator.DES_EDE3_CBC,  "DESEDE/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(CMSEnvelopedGenerator.AES128_CBC,  "AES/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(CMSEnvelopedGenerator.AES192_CBC,  "AES/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(CMSEnvelopedGenerator.AES256_CBC,  "AES/CBC/PKCS5Padding");

        MAC_ALG_NAMES.put(CMSEnvelopedGenerator.DES_EDE3_CBC,  "DESEDEMac");
        MAC_ALG_NAMES.put(CMSEnvelopedGenerator.AES128_CBC,  "AESMac");
        MAC_ALG_NAMES.put(CMSEnvelopedGenerator.AES192_CBC,  "AESMac");
        MAC_ALG_NAMES.put(CMSEnvelopedGenerator.AES256_CBC,  "AESMac");
    }

    private String getAsymmetricEncryptionAlgName(
        String encryptionAlgOID)
    {
        if (PKCSObjectIdentifiers.rsaEncryption.getId().equals(encryptionAlgOID))
        {
            return "RSA/ECB/PKCS1Padding";
        }
        
        return encryptionAlgOID;    
    }
    
    Cipher createAsymmetricCipher(
        String encryptionOid,
        Provider provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException
    {
        try
        {
            // this is reversed as the Sun policy files now allow unlimited strength RSA
            return getCipherInstance(getAsymmetricEncryptionAlgName(encryptionOid), provider);
        }
        catch (NoSuchAlgorithmException e)
        {
            return getCipherInstance(encryptionOid, provider);
        }
    }

    KeyGenerator createSymmetricKeyGenerator(
        String encryptionOID, 
        Provider provider)
        throws NoSuchAlgorithmException
    {
        try
        {
        try
        {
            return createKeyGenerator(encryptionOID, provider);
        }
        catch (NoSuchAlgorithmException e)
        {
            try
            {
                String algName = (String)BASE_CIPHER_NAMES.get(encryptionOID);
                if (algName != null)
                {
                    return createKeyGenerator(algName, provider);
                }
            }
            catch (NoSuchAlgorithmException ex)
            {
                // ignore
            }
            if (provider != null)
            {
                return createSymmetricKeyGenerator(encryptionOID, null);
            }
            throw e;
        }
        }
        catch (NoSuchProviderException e)
        {
            return createSymmetricKeyGenerator(encryptionOID, null);
        }
    }

    AlgorithmParameters createAlgorithmParameters(
        String encryptionOID, 
        Provider provider)
        throws NoSuchAlgorithmException
    {
        try
        {
            return createAlgorithmParams(encryptionOID, provider);
        }
        catch (NoSuchAlgorithmException e)
        {
            try
            {
                String algName = (String)BASE_CIPHER_NAMES.get(encryptionOID);
                if (algName != null)
                {
                    return createAlgorithmParams(algName, provider);
                }
            }
            catch (NoSuchAlgorithmException ex)
            {
                // ignore
            }
            catch (NoSuchProviderException ex)
            {
                // ignore
            }
            //
            // can't try with default provider here as parameters must be from the specified provider.
            //
            throw e;
        }
        catch (NoSuchProviderException e)
        {
             throw new NoSuchAlgorithmException("can't find provider: " + e);
        }
    }

    AlgorithmParameterGenerator createAlgorithmParameterGenerator(
        String encryptionOID,
        Provider provider)
        throws NoSuchAlgorithmException
    {
        try
        {
        try
        {
            return createAlgorithmParamsGenerator(encryptionOID, provider);
        }
        catch (NoSuchAlgorithmException e)
        {
            try
            {
                String algName = (String)BASE_CIPHER_NAMES.get(encryptionOID);
                if (algName != null)
                {
                    return createAlgorithmParamsGenerator(algName, provider);
                }
            }
            catch (NoSuchAlgorithmException ex)
            {
                // ignore
            }
            //
            // can't try with default provider here as parameters must be from the specified provider.
            //
            throw e;
        }
        }
        catch (NoSuchProviderException e)
        {
            throw new NoSuchAlgorithmException("can't find provider: " + e);
        }
    }

    String getRFC3211WrapperName(String oid)
    {
        String alg = (String)BASE_CIPHER_NAMES.get(oid);

        if (alg == null)
        {
            throw new IllegalArgumentException("no name for " + oid);
        }

        return alg + "RFC3211Wrap";
    }

    int getKeySize(String oid)
    {
        Integer keySize = (Integer)KEYSIZES.get(oid);

        if (keySize == null)
        {
            throw new IllegalArgumentException("no keysize for " + oid);
        }

        return keySize.intValue();
    }

    Cipher getCipherInstance(
        String algName,
        Provider provider)
        throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException
    {
        if (provider != null)
        {
            return Cipher.getInstance(algName, provider.getName());
        }
        else
        {
            return Cipher.getInstance(algName);
        }
    }

    private AlgorithmParameters createAlgorithmParams(
        String algName,
        Provider provider)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        if (provider != null)
        {
            return AlgorithmParameters.getInstance(algName, provider.getName());
        }
        else
        {
            return AlgorithmParameters.getInstance(algName);
        }
    }

    private AlgorithmParameterGenerator createAlgorithmParamsGenerator(
        String algName,
        Provider provider)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        if (provider != null)
        {
            return AlgorithmParameterGenerator.getInstance(algName, provider.getName());
        }
        else
        {
            return AlgorithmParameterGenerator.getInstance(algName);
        }
    }

    private KeyGenerator createKeyGenerator(
        String algName,
        Provider provider)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        if (provider != null)
        {
            return KeyGenerator.getInstance(algName, provider.getName());
        }
        else
        {
            return KeyGenerator.getInstance(algName);
        }
    }

    Cipher getSymmetricCipher(String encryptionOID, Provider provider)
        throws NoSuchAlgorithmException, NoSuchPaddingException
    {
        try
        {
        try
        {
            return getCipherInstance(encryptionOID, provider);
        }
        catch (NoSuchAlgorithmException e)
        {
            String alternate = (String)CIPHER_ALG_NAMES.get(encryptionOID);

            try
            {
                return getCipherInstance(alternate, provider);
            }
            catch (NoSuchAlgorithmException ex)
            {
                if (provider != null)
                {
                    return getSymmetricCipher(encryptionOID, null); // roll back to default
                }
                throw e;
            }
        }
        }
        catch (NoSuchProviderException e)
        {
            return getSymmetricCipher(encryptionOID, null); // roll back to default
        }
    }

    private Mac createMac(
        String algName,
        Provider provider)
        throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException
    {
        if (provider != null)
        {
            return Mac.getInstance(algName, provider.getName());
        }
        else
        {
            return Mac.getInstance(algName);
        }
    }

    Mac getMac(String macOID, Provider provider)
        throws NoSuchAlgorithmException, NoSuchPaddingException
    {
        try
        {
        try
        {
            return createMac(macOID, provider);
        }
        catch (NoSuchAlgorithmException e)
        {
            String alternate = (String)MAC_ALG_NAMES.get(macOID);

            try
            {
                return createMac(alternate, provider);
            }
            catch (NoSuchAlgorithmException ex)
            {
                if (provider != null)
                {
                    return getMac(macOID, null); // roll back to default
                }
                throw e;
            }
        }
        }
        catch (NoSuchProviderException e)
        {
            return getMac(macOID, null);
        }
    }

    AlgorithmParameters getEncryptionAlgorithmParameters(
        String encOID,
        byte[] encParams,
        Provider provider)
        throws CMSException
    {
        if (encParams == null)
        {
            return null;
        }

        try
        {
            AlgorithmParameters params = createAlgorithmParameters(encOID, provider);

            params.init(encParams, "ASN.1");

            return params;
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new CMSException("can't find parameters for algorithm", e);
        }
        catch (IOException e)
        {
            throw new CMSException("can't find parse parameters", e);
        }
    }

    String getSymmetricCipherName(String oid)
    {
        String algName = (String)BASE_CIPHER_NAMES.get(oid);
        if (algName != null)
        {
            return algName;
        }
        return oid;
    }

    static List readRecipientInfos(ASN1Set recipientInfos, byte[] contentOctets,
        AlgorithmIdentifier encAlg, AlgorithmIdentifier macAlg, AlgorithmIdentifier authEncAlg)
    {
        List infos = new ArrayList();
        for (int i = 0; i != recipientInfos.size(); i++)
        {
            RecipientInfo info = RecipientInfo.getInstance(recipientInfos.getObjectAt(i));
            InputStream contentStream = new ByteArrayInputStream(contentOctets);

            readRecipientInfo(infos, info, contentStream, encAlg, macAlg, authEncAlg);
        }
        return infos;
    }

    static List readRecipientInfos(Iterator recipientInfoIter, InputStream contentStream,
        AlgorithmIdentifier encAlg, AlgorithmIdentifier macAlg, AlgorithmIdentifier authEncAlg)
    {
        List infos = new ArrayList();
        while (recipientInfoIter.hasNext())
        {
            RecipientInfo info = (RecipientInfo)recipientInfoIter.next();

            readRecipientInfo(infos, info, contentStream, encAlg, macAlg, authEncAlg);
        }
        return infos;
    }

    private static void readRecipientInfo(List infos, RecipientInfo info, InputStream contentStream,
            AlgorithmIdentifier encAlg, AlgorithmIdentifier macAlg, AlgorithmIdentifier authEncAlg)
    {
        DEREncodable recipInfo = info.getInfo();
        if (recipInfo instanceof KeyTransRecipientInfo)
        {
            infos.add(new KeyTransRecipientInformation(
                (KeyTransRecipientInfo)recipInfo, encAlg, macAlg, authEncAlg, contentStream));
        }
        else if (recipInfo instanceof KEKRecipientInfo)
        {
            infos.add(new KEKRecipientInformation(
                (KEKRecipientInfo)recipInfo, encAlg, macAlg, authEncAlg, contentStream));
        }
        else if (recipInfo instanceof KeyAgreeRecipientInfo)
        {
            infos.add(new KeyAgreeRecipientInformation(
                (KeyAgreeRecipientInfo)recipInfo, encAlg, macAlg, authEncAlg, contentStream));
        }
        else if (recipInfo instanceof PasswordRecipientInfo)
        {
            infos.add(new PasswordRecipientInformation(
                (PasswordRecipientInfo)recipInfo, encAlg, macAlg, authEncAlg, contentStream));
        }
    }
}
