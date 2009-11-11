package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.ProviderException;
import java.security.Provider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;


/**
 * the KeyTransRecipientInformation class for a recipient who has been sent a secret
 * key encrypted using their public key that needs to be used to
 * extract the message.
 */
public class KeyTransRecipientInformation
    extends RecipientInformation
{
    private KeyTransRecipientInfo info;

    /**
     * @deprecated
     */
    public KeyTransRecipientInformation(
        KeyTransRecipientInfo   info,
        AlgorithmIdentifier     encAlg,
        InputStream             data)
    {
        this(info, encAlg, null, null, data);
    }

    /**
     * @deprecated
     */
    public KeyTransRecipientInformation(
        KeyTransRecipientInfo   info,
        AlgorithmIdentifier     encAlg,
        AlgorithmIdentifier     macAlg,
        InputStream             data)
    {
        this(info, encAlg, macAlg, null, data);
    }

    KeyTransRecipientInformation(
            KeyTransRecipientInfo   info,
            AlgorithmIdentifier     encAlg,
            AlgorithmIdentifier     macAlg,
            AlgorithmIdentifier     authEncAlg,
            InputStream             data)
    {
        super(encAlg, macAlg, authEncAlg, info.getKeyEncryptionAlgorithm(), data);

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
        byte[] encryptedKey = info.getEncryptedKey().getOctets();
        String keyExchangeAlgorithm = getExchangeEncryptionAlgorithmName(keyEncAlg.getObjectId());

        // TODO This may need looking at for AuthEnveloped case
        AlgorithmIdentifier aid = getActiveAlgID();
        String alg = CMSEnvelopedHelper.INSTANCE.getSymmetricCipherName(aid.getObjectId().getId());

        Key sKey;

        try
        {
            Cipher keyCipher = CMSEnvelopedHelper.INSTANCE.getSymmetricCipher(keyExchangeAlgorithm, prov);

            try
            {
                keyCipher.init(Cipher.UNWRAP_MODE, receiverPrivateKey);

                sKey = keyCipher.unwrap(encryptedKey, alg, Cipher.SECRET_KEY);
            }
            catch (GeneralSecurityException e)   // some providers do not support UNWRAP
            {
                keyCipher.init(Cipher.DECRYPT_MODE, receiverPrivateKey);

                sKey = new SecretKeySpec(keyCipher.doFinal(encryptedKey), alg);
            }
            catch (IllegalStateException e)   // some providers do not support UNWRAP
            {
                keyCipher.init(Cipher.DECRYPT_MODE, receiverPrivateKey);

                sKey = new SecretKeySpec(keyCipher.doFinal(encryptedKey), alg);
            }
            catch (UnsupportedOperationException e)   // some providers do not support UNWRAP
            {
                keyCipher.init(Cipher.DECRYPT_MODE, receiverPrivateKey);

                sKey = new SecretKeySpec(keyCipher.doFinal(encryptedKey), alg);
            }
            catch (ProviderException e)   // some providers do not support UNWRAP
            {
                keyCipher.init(Cipher.DECRYPT_MODE, receiverPrivateKey);

                sKey = new SecretKeySpec(keyCipher.doFinal(encryptedKey), alg);
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
