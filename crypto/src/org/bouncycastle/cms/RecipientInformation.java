package org.bouncycastle.cms;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public abstract class RecipientInformation
{
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
            return obj.getDERObject().getEncoded();
        }

        return null;
    }
    
    /**
     * return the object identifier for the key encryption algorithm.
     * @return OID for key encryption algorithm.
     */
    public String getKeyEncryptionAlgOID()
    {
        return _keyEncAlg.getObjectId().getId();
    }

    /**
     * return the ASN.1 encoded key encryption algorithm parameters, or null if
     * there aren't any.
     * @return ASN.1 encoding of key encryption algorithm parameters.
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
        return getKeyEncryptionAlgorithmParameters(CMSUtils.getProvider(provider));
    }

    /**
     * Return an AlgorithmParameters object giving the encryption parameters
     * used to encrypt the key this recipient holds.
     *
     * @param provider the provider to generate the parameters for.
     * @return the parameters object, null if there is not one.
     * @throws CMSException if the algorithm cannot be found, or the parameters can't be parsed.
     */
    public AlgorithmParameters getKeyEncryptionAlgorithmParameters(
        Provider provider)
        throws CMSException
    {
        try
        {
            byte[]  enc = this.encodeObj(_keyEncAlg.getParameters());
            if (enc == null)
            {
                return null;
            }
            
            AlgorithmParameters params = CMSEnvelopedHelper.INSTANCE.createAlgorithmParameters(getKeyEncryptionAlgOID(), provider);
            
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

    protected CMSTypedStream getContentFromSessionKey(
        Key     sKey,
        Provider  provider)
        throws CMSException
    {
        String              encAlg = _encAlg.getObjectId().getId();
        
        try
        {
            Cipher              cipher;

            cipher =  CMSEnvelopedHelper.INSTANCE.getSymmetricCipher(encAlg, provider);
           
            ASN1Object sParams = (ASN1Object)_encAlg.getParameters();
    
            if (sParams != null && !(sParams instanceof ASN1Null))
            {
                AlgorithmParameters params = CMSEnvelopedHelper.INSTANCE.createAlgorithmParameters(encAlg, cipher.getProvider());

                params.init(sParams.getEncoded(), "ASN.1");
    
                cipher.init(Cipher.DECRYPT_MODE, sKey, params);
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
        return getContent(key, CMSUtils.getProvider(provider));
    }

    public byte[] getContent(
        Key    key,
        Provider provider)
        throws CMSException
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

    public CMSTypedStream getContentStream(Key key, String provider)
        throws CMSException, NoSuchProviderException
    {
        return getContentStream(key, CMSUtils.getProvider(provider));
    }

    public abstract CMSTypedStream getContentStream(Key key, Provider provider)
        throws CMSException;
}
