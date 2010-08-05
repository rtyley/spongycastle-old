package org.bouncycastle.cms;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.cms.KEKIdentifier;
import org.bouncycastle.asn1.cms.KEKRecipientInfo;

/**
 * the RecipientInfo class for a recipient who has been sent a message
 * encrypted using a secret key known to the other side.
 */
public class KEKRecipientInformation
    extends RecipientInformation
{
        private byte[] resultMac;
    private RecipientOperator operator;
    private KEKRecipientInfo      info;

    KEKRecipientInformation(
        KEKRecipientInfo        info,
        CMSSecureReadable       secureReadable)
    {
        super(info.getKeyEncryptionAlgorithm(), secureReadable);

        this.info = info;
        this.rid = new RecipientId();
        
        KEKIdentifier kekId = info.getKekid();

        rid.setKeyIdentifier(kekId.getKeyIdentifier().getOctets());
    }

    /**
     * decrypt the content and return an input stream.
     */
    public CMSTypedStream getContentStream(
        Key      key,
        String   prov)
        throws CMSException, NoSuchProviderException
    {
        return getContentStream(key, CMSUtils.getProvider(prov));
    }

    /**
     * decrypt the content and return an input stream.
     */
    public CMSTypedStream getContentStream(
        Key      key,
        Provider prov)
        throws CMSException
    {
        try
        {
            Cipher keyCipher = CMSEnvelopedHelper.INSTANCE.createSymmetricCipher(
                keyEncAlg.getObjectId().getId(), prov);
            keyCipher.init(Cipher.UNWRAP_MODE, key);
            Key sKey = keyCipher.unwrap(info.getEncryptedKey().getOctets(), getContentAlgorithmName(),
                Cipher.SECRET_KEY);

            return getContentFromSessionKey(sKey, prov);
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
            if (operator != null)
            {
                if (operator.isMacBased())
                {
                    return operator.getMac();
                }
            }
            else
            {
                Object cryptoObject = secureReadable.getCryptoObject();
                if (cryptoObject instanceof Mac)
                {
                    resultMac = ((Mac)cryptoObject).doFinal();
                }
            }
        }

        return resultMac;
    }

    public CMSTypedStream getContentStream(Recipient recipient)
        throws CMSException, IOException
    {
        operator = ((KEKRecipient)recipient).getRecipientOperator(keyEncAlg, secureReadable.getAlgorithm(), info.getEncryptedKey().getOctets());
        
        return new CMSTypedStream(operator.getInputStream(secureReadable.getInputStream()));
    }
}
