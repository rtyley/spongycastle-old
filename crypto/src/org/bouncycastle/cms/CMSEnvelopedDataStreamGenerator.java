package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.BEROctetStringGenerator;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.RC2ParameterSpec;
import java.io.IOException;
import java.io.OutputStream;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Iterator;

/**
 * General class for generating a CMS enveloped-data message stream.
 * <p>
 * A simple example of usage.
 * <pre>
 *      CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();
 *
 *      edGen.addKeyTransRecipient(cert);
 *
 *      ByteArrayOutputStream  bOut = new ByteArrayOutputStream();
 *      
 *      OutputStream out = edGen.open(
 *                              bOut, CMSEnvelopedDataGenerator.AES128_CBC, "BC");*
 *      out.write(data);
 *      
 *      out.close();
 * </pre>
 */
public class CMSEnvelopedDataStreamGenerator
    extends CMSEnvelopedGenerator
{
    private Object              _originatorInfo = null;
    private Object              _unprotectedAttributes = null;
    private int                 _bufferSize;
    private boolean             _berEncodeRecipientSet;

    /**
     * base constructor
     */
    public CMSEnvelopedDataStreamGenerator()
    {
    }


    /**
     * Set the underlying string size for encapsulated data
     * 
     * @param bufferSize length of octet strings to buffer the data.
     */
    public void setBufferSize(
        int bufferSize)
    {
        _bufferSize = bufferSize;
    }
    
    /**
     * Use a BER Set to store the recipient information
     */
    public void setBEREncodeRecipients(
        boolean berEncodeRecipientSet)
    {
        _berEncodeRecipientSet = berEncodeRecipientSet;
    }

    private DERInteger getVersion()
    {
        if (_originatorInfo != null || _unprotectedAttributes != null)
        {
            return new DERInteger(2);
        }
        else
        {
            return new DERInteger(0);
        }
    }
    
    /**
     * generate an enveloped object that contains an CMS Enveloped Data
     * object using the given provider and the passed in key generator.
     * @throws IOException 
     */
    private OutputStream open(
        OutputStream out,
        String       encryptionOID,
        KeyGenerator keyGen,
        String       provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        String              encProvider = keyGen.getProvider().getName();
        SecretKey           encKey = keyGen.generateKey();
        AlgorithmParameters params;
        
        try
        {
            AlgorithmParameterGenerator pGen = AlgorithmParameterGenerator.getInstance(encryptionOID, encProvider);

            if (encryptionOID.equals(RC2_CBC))
            {
                byte[]  iv = new byte[8];

                //
                // mix in a bit extra...
                //
                rand.setSeed(System.currentTimeMillis());

                rand.nextBytes(iv);

                try
                {
                    pGen.init(new RC2ParameterSpec(encKey.getEncoded().length * 8, iv));
                }
                catch (InvalidAlgorithmParameterException e)
                {
                    throw new CMSException("parameters generation error: " + e, e);
                }
            }
            
            params = pGen.generateParameters();
        }
        catch (NoSuchAlgorithmException e)
        {
            params = null;
        }
        
        Iterator            it = recipientInfs.iterator();
        ASN1EncodableVector recipientInfos = new ASN1EncodableVector();
        
        while (it.hasNext())
        {
            RecipientInf            recipient = (RecipientInf)it.next();

            try
            {
                recipientInfos.add(recipient.toRecipientInfo(encKey, provider));
            }
            catch (IOException e)
            {
                throw new CMSException("encoding error.", e);
            }
            catch (InvalidKeyException e)
            {
                throw new CMSException("key inappropriate for algorithm.", e);
            }
            catch (GeneralSecurityException e)
            {
                throw new CMSException("error making encrypted content.", e);
            }
        }
        
        return open(out, encryptionOID, encKey, params, recipientInfos, encProvider);
    }
        
    protected OutputStream open(
        OutputStream        out,
        String              encryptionOID,
        SecretKey           encKey,
        AlgorithmParameters params,
        ASN1EncodableVector recipientInfos,
        String              provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        try
        {
            AlgorithmIdentifier encAlgId = getAlgorithmIdentifier(encryptionOID, params);
            
            //
            // ContentInfo
            //
            BERSequenceGenerator cGen = new BERSequenceGenerator(out);
            
            cGen.addObject(CMSObjectIdentifiers.envelopedData);
            
            //
            // Encrypted Data
            //
            BERSequenceGenerator envGen = new BERSequenceGenerator(cGen.getRawOutputStream(), 0, true);
            
            envGen.addObject(getVersion());

            if (_berEncodeRecipientSet)
            {
                envGen.getRawOutputStream().write(new BERSet(recipientInfos).getEncoded());
            }
            else
            {
                envGen.getRawOutputStream().write(new DERSet(recipientInfos).getEncoded());
            }

            Cipher cipher = Cipher.getInstance(encryptionOID, provider);
            
            cipher.init(Cipher.ENCRYPT_MODE, encKey, params);

            BERSequenceGenerator eiGen = new BERSequenceGenerator(envGen.getRawOutputStream());
            
            eiGen.addObject(PKCSObjectIdentifiers.data);
            
            eiGen.getRawOutputStream().write(encAlgId.getEncoded());
            
            BEROctetStringGenerator octGen = new BEROctetStringGenerator(eiGen.getRawOutputStream(), 0, false);
            
            CipherOutputStream      cOut;
            
            if (_bufferSize != 0)
            {
                cOut = new CipherOutputStream(octGen.getOctetOutputStream(new byte[_bufferSize]), cipher);
            }
            else
            {
                cOut = new CipherOutputStream(octGen.getOctetOutputStream(), cipher);
            }

            return new CmsEnvelopedDataOutputStream(cOut, cGen, envGen, eiGen);
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
            throw new CMSException("exception decoding algorithm parameters.", e);
        }
    }

    private AlgorithmIdentifier getAlgorithmIdentifier(String encryptionOID, AlgorithmParameters params) throws IOException
    {
        DEREncodable asn1Params;
        if (params != null)
        {
            ASN1InputStream             aIn = new ASN1InputStream(params.getEncoded("ASN.1"));
      
            asn1Params = aIn.readObject();
        }
        else
        {
            asn1Params = new DERNull();
        }
        
        AlgorithmIdentifier  encAlgId = new AlgorithmIdentifier(
                new DERObjectIdentifier(encryptionOID),
                asn1Params);
        return encAlgId;
    }
    

    
    /**
     * generate an enveloped object that contains an CMS Enveloped Data
     * object using the given provider.
     * @throws IOException 
     */
    public OutputStream open(
        OutputStream    out,
        String          encryptionOID,
        String          provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException, IOException
    {
        try
        {
            KeyGenerator keyGen = CMSEnvelopedHelper.INSTANCE.createKeyGenerator(encryptionOID, provider);
                                                    
            return open(out, encryptionOID, keyGen, provider);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new CMSException("can't find key generation algorithm.", e);
        }
    }

    /**
     * generate an enveloped object that contains an CMS Enveloped Data
     * object using the given provider.
     * @throws IOException 
     */
    public OutputStream open(
        OutputStream    out,
        String          encryptionOID,
        int             keySize,
        String          provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException, IOException
    {
        try
        {
            KeyGenerator keyGen = CMSEnvelopedHelper.INSTANCE.createKeyGenerator(encryptionOID, provider);
            
            keyGen.init(keySize);

            return open(out, encryptionOID, keyGen, provider);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new CMSException("can't find key generation algorithm.", e);
        }
    }

    private class CmsEnvelopedDataOutputStream
        extends OutputStream
    {
        private CipherOutputStream   _out;
        private BERSequenceGenerator _cGen;
        private BERSequenceGenerator _envGen;
        private BERSequenceGenerator _eiGen;
    
        public CmsEnvelopedDataOutputStream(
            CipherOutputStream   out,
            BERSequenceGenerator cGen,
            BERSequenceGenerator envGen,
            BERSequenceGenerator eiGen)
        {
            _out = out;
            _cGen = cGen;
            _envGen = envGen;
            _eiGen = eiGen;
        }
    
        public void write(
            int b)
            throws IOException
        {
            _out.write(b);
        }
        
        public void write(
            byte[] bytes,
            int    off,
            int    len)
            throws IOException
        {
            _out.write(bytes, off, len);
        }
        
        public void write(
            byte[] bytes)
            throws IOException
        {
            _out.write(bytes);
        }
        
        public void close()
            throws IOException
        {
            _out.close();
            _eiGen.close();
            
            // [TODO] unprotected attributes go here
    
            _envGen.close();
            _cGen.close();
        }
    }
}
