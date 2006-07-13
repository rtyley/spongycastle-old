package org.bouncycastle.cms;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

class CMSEnvelopedHelper
{
    static final CMSEnvelopedHelper INSTANCE = new CMSEnvelopedHelper();

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
}
