package org.bouncycastle.cms;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.ProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;


/**
 * the KeyTransRecipientInformation class for a recipient who has been sent a secret
 * key encrypted using their public key that needs to be used to
 * extract the message.
 */
public class KeyTransRecipientInformation
    extends RecipientInformation
{
    private KeyTransRecipientInfo info;

    KeyTransRecipientInformation(
        KeyTransRecipientInfo   info,
        CMSSecureReadable       secureReadable)
    {
        super(info.getKeyEncryptionAlgorithm(), secureReadable);

        this.info = info;
        this.rid = new RecipientId();

        RecipientIdentifier r = info.getRecipientIdentifier();

        try
        {
            if (r.isTagged())
            {
                ASN1OctetString octs = ASN1OctetString.getInstance(r.getId());

                rid.setSubjectKeyIdentifier(octs.getOctets());
            }
            else
            {
                IssuerAndSerialNumber   iAnds = IssuerAndSerialNumber.getInstance(r.getId());

                rid.setIssuer(iAnds.getName().getEncoded());
                rid.setSerialNumber(iAnds.getSerialNumber().getValue());
            }
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("invalid rid in KeyTransRecipientInformation");
        }
    }

    private String getExchangeEncryptionAlgorithmName(
        DERObjectIdentifier oid)
    {
        if (PKCSObjectIdentifiers.rsaEncryption.equals(oid))
        {
            return "RSA/ECB/PKCS1Padding";
        }
        
        return oid.getId();
    }

    protected Key getSessionKey(Key receiverPrivateKey, Provider prov)
        throws CMSException
    {
        CMSEnvelopedHelper helper = CMSEnvelopedHelper.INSTANCE;

        String keyExchangeAlgorithm = getExchangeEncryptionAlgorithmName(keyEncAlg.getObjectId());

        try
        {
            Key sKey = null;

            Cipher keyCipher = helper.createAsymmetricCipher(keyExchangeAlgorithm, prov);

            byte[] encryptedKeyBytes = info.getEncryptedKey().getOctets();
            String contentAlgorithmName = getContentAlgorithmName();

            try
            {
                keyCipher.init(Cipher.UNWRAP_MODE, receiverPrivateKey);
                sKey = keyCipher.unwrap(encryptedKeyBytes, contentAlgorithmName, Cipher.SECRET_KEY);
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
                keyCipher.init(Cipher.DECRYPT_MODE, receiverPrivateKey);
                sKey = new SecretKeySpec(keyCipher.doFinal(encryptedKeyBytes), contentAlgorithmName);
            }

            return sKey;
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
        catch (IllegalBlockSizeException e)
        {
            throw new CMSException("illegal blocksize in message.", e);
        }
        catch (BadPaddingException e)
        {
            throw new CMSException("bad padding in message.", e);
        }
    }

    /**
     * decrypt the content and return it
     */
    public CMSTypedStream getContentStream(
        Key key,
        String prov)
        throws CMSException, NoSuchProviderException
    {
        return getContentStream(key, CMSUtils.getProvider(prov));
    }

    public CMSTypedStream getContentStream(
        Key key,
        Provider prov)
        throws CMSException
    {
        Key sKey = getSessionKey(key, prov);

        return getContentFromSessionKey(sKey, prov);
    }
}
