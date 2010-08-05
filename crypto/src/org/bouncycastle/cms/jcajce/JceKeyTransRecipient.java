package org.bouncycastle.cms.jcajce;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyTransRecipient;

public abstract class JceKeyTransRecipient
    implements KeyTransRecipient
{
    private PrivateKey recipientKey;
    protected EnvelopedDataHelper helper = new DefaultEnvelopedDataHelper();

    public JceKeyTransRecipient(PrivateKey recipientKey)
    {
        this.recipientKey = recipientKey;
    }

    public JceKeyTransRecipient setProvider(Provider provider)
    {
        this.helper = new ProviderEnvelopedDataHelper(provider);

        return this;
    }

    public JceKeyTransRecipient setProvider(String providerName)
    {
        this.helper = new NamedEnvelopedDataHelper(providerName);

        return this;
    }

    protected Key extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        try
        {
            Key sKey = null;

            Cipher keyCipher = helper.createCipher(keyEncryptionAlgorithm.getAlgorithm());

            try
            {
                keyCipher.init(Cipher.UNWRAP_MODE, recipientKey);
                sKey = keyCipher.unwrap(encryptedContentEncryptionKey, contentEncryptionAlgorithm.getAlgorithm().getId(), Cipher.SECRET_KEY);
            }
            catch (GeneralSecurityException e)
            {
            }
            catch (IllegalStateException e)
            {
            }
            catch (UnsupportedOperationException e)
            {
            }
            catch (ProviderException e)
            {
            }

            // some providers do not support UNWRAP (this appears to be only for asymmetric algorithms)
            if (sKey == null)
            {
                keyCipher.init(Cipher.DECRYPT_MODE, recipientKey);
                sKey = new SecretKeySpec(keyCipher.doFinal(encryptedContentEncryptionKey), contentEncryptionAlgorithm.getAlgorithm().getId());
            }

            return sKey;
        }
        catch (InvalidKeyException e)
        {
            throw new CMSException("key invalid in message.", e);
        }
        catch (IllegalBlockSizeException e)
        {
            throw new CMSException("illegal blocksize in message.", e);
        }
        catch (BadPaddingException e)
        {
            throw new CMSException("bad padding in message.", e);
        }
    }
}
