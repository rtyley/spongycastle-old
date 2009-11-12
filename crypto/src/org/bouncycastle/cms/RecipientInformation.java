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
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public abstract class RecipientInformation
{
    protected RecipientId rid = new RecipientId();
    protected AlgorithmIdentifier encAlg;
    protected AlgorithmIdentifier macAlg;
    protected AlgorithmIdentifier authEncAlg;
    protected AlgorithmIdentifier keyEncAlg;
    protected InputStream data;

    private MacInputStream macStream;
    private byte[]         resultMac;

    /**
     * @deprecated
     */
    protected RecipientInformation(
        AlgorithmIdentifier encAlg,
        AlgorithmIdentifier keyEncAlg,
        InputStream data)
    {
        this(encAlg, null, keyEncAlg, data);
    }

    /**
     * @deprecated
     */
    protected RecipientInformation(
        AlgorithmIdentifier encAlg,
        AlgorithmIdentifier macAlg,
        AlgorithmIdentifier keyEncAlg,
        InputStream data)
    {
        this(encAlg, macAlg, null, keyEncAlg, data);
    }

    RecipientInformation(
        AlgorithmIdentifier encAlg,
        AlgorithmIdentifier macAlg,
        AlgorithmIdentifier authEncAlg,
        AlgorithmIdentifier keyEncAlg,
        InputStream data)
    {
        this.encAlg = encAlg;
        this.macAlg = macAlg;
        this.authEncAlg = authEncAlg;
        this.keyEncAlg = keyEncAlg;
        this.data = data;
    }

    AlgorithmIdentifier getActiveAlgID()
    {
        if (encAlg != null)
        {
            return encAlg;
        }
        if (macAlg != null)
        {
            return macAlg;
        }
        return authEncAlg;
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

        try
        {
            InputStream content = data;

            // If encrypted, need to wrap in CipherInputStream to decrypt
            if (encAlg != null)
            {
                String encAlg = this.encAlg.getObjectId().getId();
                Cipher cipher = CMSEnvelopedHelper.INSTANCE.getSymmetricCipher(encAlg, provider);

                ASN1Object sParams = (ASN1Object)this.encAlg.getParameters();

                if (sParams != null && !(sParams instanceof ASN1Null))
                {
                    try
                    {
                        AlgorithmParameters params = CMSEnvelopedHelper.INSTANCE.createAlgorithmParameters(encAlg, cipher.getProvider());

                        params.init(sParams.getEncoded(), "ASN.1");

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
                            cipher.init(Cipher.DECRYPT_MODE, sKey, new IvParameterSpec(ASN1OctetString.getInstance(sParams).getOctets()));
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

                content = new CipherInputStream(content, cipher); 
            }

            // If authenticated, need to wrap in MacInputStream to calculate MAC
            if (macAlg != null)
            {
                content = macStream = createMacInputStream(macAlg, sKey, content, provider);
            }

            if (authEncAlg != null)
            {
                // TODO Create AEAD cipher instance to decrypt and calculate tag ( MAC)
                throw new CMSException("AuthEnveloped data decryption not yet implemented");

//              RFC 5084 ASN.1 Module
//                -- Parameters for AigorithmIdentifier
//
//                CCMParameters ::= SEQUENCE {
//                  aes-nonce         OCTET STRING (SIZE(7..13)),
//                  aes-ICVlen        AES-CCM-ICVlen DEFAULT 12 }
//
//                AES-CCM-ICVlen ::= INTEGER (4 | 6 | 8 | 10 | 12 | 14 | 16)
//
//                GCMParameters ::= SEQUENCE {
//                  aes-nonce        OCTET STRING, -- recommended size is 12 octets
//                  aes-ICVlen       AES-GCM-ICVlen DEFAULT 12 }
//
//                AES-GCM-ICVlen ::= INTEGER (12 | 13 | 14 | 15 | 16)
            }

            return new CMSTypedStream(content);
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
        catch (InvalidParameterSpecException e)
        {
            throw new CMSException("MAC algorithm parameter spec invalid.", e);
        }
        catch (IOException e)
        {
            throw new CMSException("error decoding algorithm parameters.", e);
        }
    }

    private static MacInputStream createMacInputStream(AlgorithmIdentifier macAlg, Key sKey, InputStream inStream, Provider provider)
        throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, InvalidParameterSpecException
    {
        Mac mac = CMSEnvelopedHelper.INSTANCE.getMac(macAlg.getObjectId().getId(), provider);

        ASN1Object sParams = (ASN1Object)macAlg.getParameters();

        if (sParams != null && !(sParams instanceof ASN1Null))
        {
            AlgorithmParameters params = CMSEnvelopedHelper.INSTANCE.createAlgorithmParameters(macAlg.getObjectId().getId(), provider);

            params.init(sParams.getEncoded(), "ASN.1");

            mac.init(sKey, params.getParameterSpec(IvParameterSpec.class));
        }
        else
        {
            mac.init(sKey);
        }

        return new MacInputStream(mac, inStream);
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
            if (data instanceof ByteArrayInputStream)
            {
                data.reset();
            }

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
        if (macStream != null && resultMac == null)
        {
            resultMac = macStream.getMac();
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


    private static class MacInputStream
        extends InputStream
    {
        private final InputStream inStream;
        private final Mac mac;

        MacInputStream(Mac mac, InputStream inStream)
        {
            this.inStream = inStream;
            this.mac = mac;
        }

        public int read(byte[] buf)
            throws IOException
        {
            return read(buf, 0, buf.length);
        }

        public int read(byte[] buf, int off, int len)
            throws IOException
        {
            int i = inStream.read(buf, off, len);

            if (i > 0)
            {
                mac.update(buf, off, i);
            }

            return i;
        }

        public int read()
            throws IOException
        {
            int i = inStream.read();

            if (i > 0)
            {
                mac.update((byte)i);
            }

            return i;
        }

        public byte[] getMac()
        {
            return mac.doFinal();
        }
    }
}
