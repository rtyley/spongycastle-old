package org.bouncycastle.cms;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public abstract class RecipientInformation
{
    protected RecipientId rid = new RecipientId();
    protected AlgorithmIdentifier   keyEncAlg;
    protected CMSSecureReadable     secureReadable;

    private byte[] resultMac;

    RecipientInformation(
        AlgorithmIdentifier     keyEncAlg,
        CMSSecureReadable       secureReadable)
    {
        this.keyEncAlg = keyEncAlg;
        this.secureReadable = secureReadable;
    }

    String getContentAlgorithmName()
    {
        AlgorithmIdentifier algorithm = secureReadable.getAlgorithm();
        return CMSEnvelopedHelper.INSTANCE.getSymmetricCipherName(algorithm.getObjectId().getId());
    }

    public RecipientId getRID()
    {
        return rid;
    }

    private byte[] encodeObj(
        DEREncodable obj)
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
     *
     * @return OID for key encryption algorithm.
     */
    public String getKeyEncryptionAlgOID()
    {
        return keyEncAlg.getObjectId().getId();
    }

    /**
     * return the ASN.1 encoded key encryption algorithm parameters, or null if
     * there aren't any.
     *
     * @return ASN.1 encoding of key encryption algorithm parameters.
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
     * @throws CMSException            if the algorithm cannot be found, or the parameters can't be parsed.
     * @throws NoSuchProviderException if the provider cannot be found.
     */
    public AlgorithmParameters getKeyEncryptionAlgorithmParameters(
        String provider)
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
            byte[] enc = this.encodeObj(keyEncAlg.getParameters());
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
        Key sKey,
        Provider provider)
        throws CMSException
    {
        CMSReadable readable = secureReadable.getReadable((SecretKey)sKey, provider); 

        try
        {
            return new CMSTypedStream(readable.read());
        }
        catch (IOException e)
        {
            throw new CMSException("error getting .", e);
        }
    }

    public byte[] getContent(
        Key key,
        String provider)
        throws CMSException, NoSuchProviderException
    {
        return getContent(key, CMSUtils.getProvider(provider));
    }

    public byte[] getContent(
        Key key,
        Provider provider)
        throws CMSException
    {
        try
        {
            return CMSUtils.streamToByteArray(getContentStream(key, provider).getContentStream());
        }
        catch (IOException e)
        {
            throw new RuntimeException("unable to parse internal stream: " + e);
        }
    }

    /**
     * Return the MAC calculated for the content stream. Note: this call is only meaningful once all
     * the content has been read.
     *
     * @return  byte array containing the mac.
     */
    public byte[] getMac()
    {
        if (resultMac == null)
        {
            Object cryptoObject = secureReadable.getCryptoObject();
            if (cryptoObject instanceof Mac)
            {
                resultMac = ((Mac)cryptoObject).doFinal();
            }
        }

        return resultMac;
    }

    public CMSTypedStream getContentStream(Key key, String provider)
        throws CMSException, NoSuchProviderException
    {
        return getContentStream(key, CMSUtils.getProvider(provider));
    }

    public abstract CMSTypedStream getContentStream(Key key, Provider provider)
        throws CMSException;
}
