package org.bouncycastle.cms;

import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.cms.KEKIdentifier;
import org.bouncycastle.asn1.cms.KEKRecipientInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * the RecipientInfo class for a recipient who has been sent a message
 * encrypted using a secret key known to the other side.
 */
public class KEKRecipientInformation
    extends RecipientInformation
{
    private KEKRecipientInfo      info;

    /**
     * @deprecated
     */
    public KEKRecipientInformation(
        KEKRecipientInfo        info,
        AlgorithmIdentifier     encAlg,
        InputStream             data)
    {
        this(info, encAlg, null, data);
    }

    public KEKRecipientInformation(
        KEKRecipientInfo        info,
        AlgorithmIdentifier     encAlg,
        AlgorithmIdentifier     macAlg,
        InputStream             data)
    {
        super(encAlg, macAlg, AlgorithmIdentifier.getInstance(info.getKeyEncryptionAlgorithm()), data);
        
        this.info = info;
        this.rid = new RecipientId();
        
        KEKIdentifier       kekId = info.getKekid();

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
            byte[]              encryptedKey = info.getEncryptedKey().getOctets();
            Cipher              keyCipher = Cipher.getInstance(keyEncAlg.getObjectId().getId(), prov);

            keyCipher.init(Cipher.UNWRAP_MODE, key);

            AlgorithmIdentifier aid = encAlg;
            if (aid == null)
            {
                aid = macAlg;
            }
            
            String              alg = aid.getObjectId().getId();
            Key                 sKey = keyCipher.unwrap(
                                        encryptedKey, alg, Cipher.SECRET_KEY);

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
}
