package org.bouncycastle.cms;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public abstract class RecipientInformation
{
    private static final ASN1Null   asn1Null = new DERNull();
    
    protected RecipientId           _rid = new RecipientId();
    protected AlgorithmIdentifier   _encAlg;
    protected AlgorithmIdentifier   _keyEncAlg;
    protected InputStream           _data;

    protected RecipientInformation(
        AlgorithmIdentifier encAlg,
        AlgorithmIdentifier keyEncAlg,
        InputStream         data)
    {
        this._encAlg = encAlg;
        this._keyEncAlg = keyEncAlg;
        this._data = data;
    }
    
    public RecipientId getRID()
    {
        return _rid;
    }
    
    private byte[] encodeObj(
        DEREncodable    obj)
        throws IOException
    {
        if (obj != null)
        {
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
            ASN1OutputStream        aOut = new ASN1OutputStream(bOut);

            aOut.writeObject(obj);

            return bOut.toByteArray();
        }

        return null;
    }
    
    /**
     * return the object identifier for the key encryption algorithm.
     */
    public String getKeyEncryptionAlgOID()
    {
        return _keyEncAlg.getObjectId().getId();
    }

    /**
     * return the ASN.1 encoded key encryption algorithm parameters, or null if
     * there aren't any.
     */
    public byte[] getKeyEncryptionAlgParams()
    {
        try
        {
            return encodeObj(_keyEncAlg.getParameters());
        }
        catch (Exception e)
        {
            throw new RuntimeException("exception getting encryption parameters " + e);
        }
    }
    
    /**
     * Return an AlgorithmParameters object giving the encryption parameters
     * used to encrypt the key this recipient holds.
     * 
     * @param provider the provider to generate the parameters for.
     * @return the parameters object, null if there is not one.
     * @throws CMSException if the algorithm cannot be found, or the parameters can't be parsed.
     * @throws NoSuchProviderException if the provider cannot be found.
     */
    public AlgorithmParameters getKeyEncryptionAlgorithmParameters(
        String  provider) 
        throws CMSException, NoSuchProviderException    
    {        
        try
        {
            byte[]  enc = this.encodeObj(_keyEncAlg.getParameters());
            if (enc == null)
            {
                return null;
            }
            
            AlgorithmParameters params;
            
            try
            {
                params = AlgorithmParameters.getInstance(getKeyEncryptionAlgOID(), provider);
            }
            catch (NoSuchAlgorithmException e)
            {
                params = AlgorithmParameters.getInstance(getKeyEncryptionAlgOID());
            }
            
            params.init(enc, "ASN.1");
            
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
    
    protected String getDataEncryptionAlgorithmName(
        DERObjectIdentifier oid)
    {
        if (NISTObjectIdentifiers.id_aes128_CBC.equals(oid))
        {
            return "AES";
        }
        else if (NISTObjectIdentifiers.id_aes192_CBC.equals(oid))
        {
            return "AES";
        }
        else if (NISTObjectIdentifiers.id_aes256_CBC.equals(oid))
        {
            return "AES";
        }
        
        return oid.getId();
    }
    
    private String getDataEncryptionCipherName(
        DERObjectIdentifier oid)
    {
        if (NISTObjectIdentifiers.id_aes128_CBC.equals(oid))
        {
            return "AES/CBC/PKCS5Padding";
        }
        else if (NISTObjectIdentifiers.id_aes192_CBC.equals(oid))
        {
            return "AES/CBC/PKCS5Padding";
        }
        else if (NISTObjectIdentifiers.id_aes256_CBC.equals(oid))
        {
            return "AES/CBC/PKCS5Padding";
        }
        
        return oid.getId();
    }
    
    protected CMSTypedStream getContentFromSessionKey(
        Key     sKey,
        String  provider)
        throws CMSException, NoSuchProviderException
    {
        String              alg = getDataEncryptionAlgorithmName(_encAlg.getObjectId());
        
        try
        {
            Cipher              cipher;
            String              cipherName = getDataEncryptionCipherName(_encAlg.getObjectId());
            
            try
            {
                cipher = Cipher.getInstance(cipherName, provider);
            }
            catch (NoSuchAlgorithmException e)
            {
                cipher = Cipher.getInstance(cipherName);
            }
            
            DEREncodable        sParams = _encAlg.getParameters();
    
            if (sParams != null && !asn1Null.equals(sParams))
            {
                AlgorithmParameters     params;
                
                try
                {
                    params = AlgorithmParameters.getInstance(alg, provider);
                }
                catch (NoSuchAlgorithmException e)
                {
                    params = AlgorithmParameters.getInstance(alg);
                }
    
                ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
                ASN1OutputStream        aOut = new ASN1OutputStream(bOut);
    
                aOut.writeObject(_encAlg.getParameters());
    
                params.init(bOut.toByteArray(), "ASN.1");
    
                cipher.init(Cipher.DECRYPT_MODE, sKey, params);
            }
            else
            {
                if (alg.equals(CMSEnvelopedDataGenerator.DES_EDE3_CBC)
                    || alg.equals(CMSEnvelopedDataGenerator.IDEA_CBC)
                    || alg.equals(CMSEnvelopedDataGenerator.CAST5_CBC))
                {
                    cipher.init(Cipher.DECRYPT_MODE, sKey, new IvParameterSpec(new byte[8]));
                }
                else
                {
                    cipher.init(Cipher.DECRYPT_MODE, sKey);
                }
            }
    
            return new CMSTypedStream(new CipherInputStream(_data, cipher));
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new CMSException("can't find algorithm.", e);
        }
        catch (InvalidKeyException e)
        {
            throw new CMSException("key invalid in message.", e);
        }
        catch (NoSuchPaddingException e)
        {
            throw new CMSException("required padding not supported.", e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new CMSException("algorithm parameters invalid.", e);
        }
        catch (IOException e)
        {
            throw new CMSException("error decoding algorithm parameters.", e);
        }
    }
    
    public byte[] getContent(
        Key    key,
        String provider)
        throws CMSException, NoSuchProviderException
    {
        try
        {
            if (_data instanceof ByteArrayInputStream)
            {
                _data.reset();
            }
            
            return CMSUtils.streamToByteArray(getContentStream(key, provider).getContentStream());
        }
        catch (IOException e)
        {
            throw new RuntimeException("unable to parse internal stream: " + e);
        }
    }
    
    abstract public CMSTypedStream getContentStream(Key key, String provider)
        throws CMSException, NoSuchProviderException;
}
