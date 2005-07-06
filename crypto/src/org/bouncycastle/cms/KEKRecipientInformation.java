package org.bouncycastle.cms;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.cms.EncryptedContentInfo;
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
    private KEKRecipientInfo        info;

    public KEKRecipientInformation(
        KEKRecipientInfo        info,
        EncryptedContentInfo    data)
    {
        super(AlgorithmIdentifier.getInstance(info.getKeyEncryptionAlgorithm()), data);
        
        this.info = info;
        this.rid = new RecipientId();
        
        KEKIdentifier       kekId = info.getKekid();

        rid.setKeyIdentifier(kekId.getKeyIdentifier().getOctets());
    }

    /**
     * decrypt the content and return it as a byte array.
     */
    public byte[] getContent(
        Key      key,
        String   prov)
        throws CMSException, NoSuchProviderException
    {
        try
        {
            byte[]              encryptedKey = info.getEncryptedKey().getOctets();
            Cipher              keyCipher = Cipher.getInstance(keyEncAlg.getObjectId().getId(), prov);

            keyCipher.init(Cipher.UNWRAP_MODE, key);

            byte[]              enc = data.getEncryptedContent().getOctets();
            AlgorithmIdentifier aid = data.getContentEncryptionAlgorithm();
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
