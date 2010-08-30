package org.bouncycastle.cms;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Iterator;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.BERConstructedOctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AuthenticatedData;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.GenericKey;

/**
 * General class for generating a CMS authenticated-data message.
 *
 * A simple example of usage.
 *
 * <pre>
 *      CMSAuthenticatedDataGenerator  fact = new CMSAuthenticatedDataGenerator();
 *
 *      fact.addKeyTransRecipient(cert);
 *
 *      CMSAuthenticatedData         data = fact.generate(content, algorithm, "BC");
 * </pre>
 */
public class CMSAuthenticatedDataGenerator
    extends CMSAuthenticatedGenerator
{
    /**
     * base constructor
     */
    public CMSAuthenticatedDataGenerator()
    {
    }

    /**
     * constructor allowing specific source of randomness
     * @param rand instance of SecureRandom to use
     */
    public CMSAuthenticatedDataGenerator(
        SecureRandom rand)
    {
        super(rand);
    }

    /**
     * generate an enveloped object that contains an CMS Enveloped Data
     * object using the given provider and the passed in key generator.
     */
    private CMSAuthenticatedData generate(
        CMSProcessable  content,
        String          macOID,
        KeyGenerator    keyGen,
        Provider        provider)
        throws NoSuchAlgorithmException, CMSException
    {
        Provider                encProvider = keyGen.getProvider();
        ASN1EncodableVector     recipientInfos = new ASN1EncodableVector();
        AlgorithmIdentifier     macAlgId;
        SecretKey               encKey;
        ASN1OctetString         encContent;
        ASN1OctetString         macResult;

        try
        {
            Mac mac = CMSEnvelopedHelper.INSTANCE.getMac(macOID, encProvider);

            AlgorithmParameterSpec params;

            encKey = keyGen.generateKey();
            params = generateParameterSpec(macOID, encKey, encProvider);

            mac.init(encKey, params);

            macAlgId = getAlgorithmIdentifier(macOID, params, encProvider);

            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
            MacOutputStream         mOut = new MacOutputStream(bOut, mac);

            content.write(mOut);

            mOut.close();
            bOut.close();

            encContent = new BERConstructedOctetString(bOut.toByteArray());

            macResult = new DEROctetString(mOut.getMac());
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
        catch (InvalidParameterSpecException e)
        {
           throw new CMSException("exception setting up parameters.", e);
        }

        Iterator it = oldRecipientInfoGenerators.iterator();

        while (it.hasNext())
        {
            IntRecipientInfoGenerator recipient = (IntRecipientInfoGenerator)it.next();

            try
            {
                recipientInfos.add(recipient.generate(encKey, rand, provider));
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

        for (it = recipientInfoGenerators.iterator(); it.hasNext();)
        {
            RecipientInfoGenerator recipient = (RecipientInfoGenerator)it.next();

            recipientInfos.add(recipient.generate(new GenericKey(encKey)));
        }

        ContentInfo  eci = new ContentInfo(
                CMSObjectIdentifiers.data,
                encContent);

        ContentInfo contentInfo = new ContentInfo(
                CMSObjectIdentifiers.authenticatedData,
                new AuthenticatedData(null, new DERSet(recipientInfos), macAlgId, null, eci, null, macResult, null));

        return new CMSAuthenticatedData(contentInfo);
    }

    /**
     * generate an authenticated object that contains an CMS Authenticated Data
     * object using the given provider.
     */
    public CMSAuthenticatedData generate(
        CMSProcessable  content,
        String          macOID,
        String          provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        return generate(content, macOID, CMSUtils.getProvider(provider));
    }

    /**
     * generate an authenticated object that contains an CMS Authenticated Data
     * object using the given provider.
     */
    public CMSAuthenticatedData generate(
        CMSProcessable  content,
        String          encryptionOID,
        Provider        provider)
        throws NoSuchAlgorithmException, CMSException
    {
        KeyGenerator keyGen = CMSEnvelopedHelper.INSTANCE.createSymmetricKeyGenerator(encryptionOID, provider);

        keyGen.init(rand);

        return generate(content, encryptionOID, keyGen, provider);
    }
}