package org.bouncycastle.cms;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public abstract class RecipientInformation
{
    private static ASN1Null         asn1Null = new DERNull();
    
    protected RecipientId             rid = new RecipientId();
    protected AlgorithmIdentifier     keyEncAlg;
    protected EncryptedContentInfo    data;

    protected RecipientInformation(
        AlgorithmIdentifier     keyEncAlg,
        EncryptedContentInfo    data)
    {
        this.keyEncAlg = keyEncAlg;
        this.data = data;
    }
    
    public RecipientId getRID()
    {
        return rid;
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
        return keyEncAlg.getObjectId().getId();
    }

    /**
     * return the ASN.1 encoded key encryption algorithm parameters, or null if
     * there aren't any.
     */
    public byte[] getKeyEncryptionAlgParams()
    {
        try
        {
            return encodeObj(keyEncAlg.getParameters());
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
            byte[]  enc = this.encodeObj(keyEncAlg.getParameters());
            if (enc == null)
            {
                return null;
            }
            
            AlgorithmParameters params = AlgorithmParameters.getInstance(getKeyEncryptionAlgOID(), provider); 
            
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
    
    protected byte[] getContentFromSessionKey(
        Key     sKey,
        String  provider)
        throws CMSException, NoSuchProviderException
    {
        AlgorithmIdentifier aid = data.getContentEncryptionAlgorithm();
        String              alg = aid.getObjectId().getId();
        byte[]              enc = data.getEncryptedContent().getOctets();
        
        try
        {
            Cipher              cipher = Cipher.getInstance(alg, provider);
            DEREncodable        sParams = aid.getParameters();
    
            if (sParams != null && !asn1Null.equals(sParams))
            {
                AlgorithmParameters     params = AlgorithmParameters.getInstance(alg, provider);
    
                ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
                ASN1OutputStream        aOut = new ASN1OutputStream(bOut);
    
                aOut.writeObject(aid.getParameters());
    
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
    
            return cipher.doFinal(enc);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new CMSException("can't find algorithm.", e);
        }
        catch (IllegalBlockSizeException e)
        {
            throw new CMSException("illegal blocksize in message.", e);
        }
        catch (InvalidKeyException e)
        {
            throw new CMSException("key invalid in message.", e);
        }
        catch (NoSuchPaddingException e)
        {
            throw new CMSException("required padding not supported.", e);
        }
        catch (BadPaddingException e)
        {
            throw new CMSException("bad padding in message.", e);
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
        
    abstract public byte[] getContent(Key key, String provider)
        throws CMSException, NoSuchProviderException;
}
