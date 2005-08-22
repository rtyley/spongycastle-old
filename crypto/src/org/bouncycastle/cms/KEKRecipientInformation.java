package org.bouncycastle.cms;

import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

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
    private KEKRecipientInfo      _info;
    private AlgorithmIdentifier   _encAlg;

    public KEKRecipientInformation(
        KEKRecipientInfo        info,
        AlgorithmIdentifier     encAlg,
        InputStream             data)
    {
        super(encAlg, AlgorithmIdentifier.getInstance(info.getKeyEncryptionAlgorithm()), data);
        
        this._info = info;
        this._encAlg = encAlg;
        this._rid = new RecipientId();
        
        KEKIdentifier       kekId = info.getKekid();

        _rid.setKeyIdentifier(kekId.getKeyIdentifier().getOctets());
    }

    /**
     * decrypt the content and return an input stream.
     */
    public CMSTypedStream getContentStream(
        Key      key,
        String   prov)
        throws CMSException, NoSuchProviderException
    {
        try
        {
            byte[]              encryptedKey = _info.getEncryptedKey().getOctets();
            Cipher              keyCipher = Cipher.getInstance(_keyEncAlg.getObjectId().getId(), prov);

            keyCipher.init(Cipher.UNWRAP_MODE, key);

            AlgorithmIdentifier aid = _encAlg;
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
