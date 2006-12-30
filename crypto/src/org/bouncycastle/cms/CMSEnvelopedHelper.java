package org.bouncycastle.cms;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.HashMap;
import java.util.Map;

class CMSEnvelopedHelper
{
    static final CMSEnvelopedHelper INSTANCE = new CMSEnvelopedHelper();

    private static final Map KEYSIZES = new HashMap();
    private static final Map CIPHERS = new HashMap();

    static
    {
        KEYSIZES.put(CMSEnvelopedGenerator.DES_EDE3_CBC,  new Integer(192));
        KEYSIZES.put(CMSEnvelopedGenerator.AES128_CBC,  new Integer(128));
        KEYSIZES.put(CMSEnvelopedGenerator.AES192_CBC,  new Integer(192));
        KEYSIZES.put(CMSEnvelopedGenerator.AES256_CBC,  new Integer(256));

        CIPHERS.put(CMSEnvelopedGenerator.DES_EDE3_CBC,  "DESEDE");
        CIPHERS.put(CMSEnvelopedGenerator.AES128_CBC,  "AES");
        CIPHERS.put(CMSEnvelopedGenerator.AES192_CBC,  "AES");
        CIPHERS.put(CMSEnvelopedGenerator.AES256_CBC,  "AES");
    }

    private String getEncryptionAlgName(
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
        String provider) 
        throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException
    {
        try
        {
            return Cipher.getInstance(encryptionOid, provider);
        }
        catch (NoSuchAlgorithmException e)
        {
            return Cipher.getInstance(getEncryptionAlgName(encryptionOid), provider);
        }
    }
    
    KeyGenerator createKeyGenerator(
        String encryptionOID, 
        String provider) 
        throws NoSuchProviderException, NoSuchAlgorithmException
    {
        KeyGenerator keyGen;
        
        try
        {
            keyGen = KeyGenerator.getInstance(encryptionOID, provider);
        }
        catch (NoSuchAlgorithmException e)
        {
            keyGen = KeyGenerator.getInstance(encryptionOID);
        }
        return keyGen;
    }

    String getRFC3211WrapperName(String oid)
    {
        String alg = (String)CIPHERS.get(oid);

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
}
