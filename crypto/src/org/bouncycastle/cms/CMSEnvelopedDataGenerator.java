package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.BERConstructedOctetString;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.RC2ParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Iterator;

/**
 * General class for generating a CMS enveloped-data message.
 *
 * A simple example of usage.
 *
 * <pre>
 *      CMSEnvelopedDataGenerator  fact = new CMSEnvelopedDataGenerator();
 *
 *      fact.addKeyTransRecipient(cert);
 *
 *      CMSEnvelopedData         data = fact.generate(content, algorithm, "BC");
 * </pre>
 */
public class CMSEnvelopedDataGenerator
    extends CMSEnvelopedGenerator
{
    /**
     * base constructor
     */
    public CMSEnvelopedDataGenerator()
    {
    }

    /**
     * generate an enveloped object that contains an CMS Enveloped Data
     * object using the given provider and the passed in key generator.
     */
    private CMSEnvelopedData generate(
        CMSProcessable  content,
        String          encryptionOID,
        KeyGenerator    keyGen,
        String          provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        String                  encProviderName = keyGen.getProvider().getName();
        ASN1EncodableVector     recipientInfos = new ASN1EncodableVector();
        AlgorithmIdentifier     encAlgId;
        SecretKey               encKey;
        ASN1OctetString         encContent;

        try
        {
            Cipher              cipher = Cipher.getInstance(encryptionOID, encProviderName);

            AlgorithmParameters params;
            DEREncodable        asn1Params;
            
            encKey = keyGen.generateKey();

            try
            {
                AlgorithmParameterGenerator pGen = AlgorithmParameterGenerator.getInstance(encryptionOID, encProviderName);

                if (encryptionOID.equals(RC2_CBC))
                {
                    byte[]  iv = new byte[8];

                    //
                    // mix in a bit extra...
                    //
                    rand.setSeed(System.currentTimeMillis());

                    rand.nextBytes(iv);

                    pGen.init(new RC2ParameterSpec(encKey.getEncoded().length * 8, iv));
                }
                
                params = pGen.generateParameters();

                ASN1InputStream             aIn = new ASN1InputStream(params.getEncoded("ASN.1"));

                asn1Params = aIn.readObject();
            }
            catch (NoSuchAlgorithmException e)
            {
                params = null;
                asn1Params = new DERNull();
            }

            encAlgId = new AlgorithmIdentifier(
                                new DERObjectIdentifier(encryptionOID),
                                asn1Params);

            cipher.init(Cipher.ENCRYPT_MODE, encKey, params);

            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
            CipherOutputStream      cOut = new CipherOutputStream(bOut, cipher);

            content.write(cOut);

            cOut.close();

            encContent = new BERConstructedOctetString(bOut.toByteArray());
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

        Iterator            it = recipientInfs.iterator();

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

        EncryptedContentInfo  eci = new EncryptedContentInfo(
                                 PKCSObjectIdentifiers.data,
                                 encAlgId, 
                                 encContent);

        ContentInfo contentInfo = new ContentInfo(
                PKCSObjectIdentifiers.envelopedData,
                new EnvelopedData(null, new DERSet(recipientInfos), eci, null));

        return new CMSEnvelopedData(contentInfo);
    }
    
    /**
     * generate an enveloped object that contains an CMS Enveloped Data
     * object using the given provider.
     */
    public CMSEnvelopedData generate(
        CMSProcessable  content,
        String          encryptionOID,
        String          provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        KeyGenerator keyGen = CMSEnvelopedHelper.INSTANCE.createKeyGenerator(encryptionOID, provider);

        return generate(content, encryptionOID, keyGen, provider);
    }


    /**
     * generate an enveloped object that contains an CMS Enveloped Data
     * object using the given provider.
     */
    public CMSEnvelopedData generate(
        CMSProcessable  content,
        String          encryptionOID,
        int             keySize,
        String          provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        KeyGenerator keyGen = CMSEnvelopedHelper.INSTANCE.createKeyGenerator(encryptionOID, provider);

        keyGen.init(keySize);

        return generate(content, encryptionOID, keyGen, provider);
    }
}
