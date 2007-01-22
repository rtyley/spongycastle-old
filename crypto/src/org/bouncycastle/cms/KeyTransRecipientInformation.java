package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;


/**
 * the KeyTransRecipientInformation class for a recipient who has been sent a secret
 * key encrypted using their public key that needs to be used to
 * extract the message.
 */
public class KeyTransRecipientInformation
    extends RecipientInformation
{
    private KeyTransRecipientInfo _info;
    private AlgorithmIdentifier   _encAlg;

    public KeyTransRecipientInformation(
        KeyTransRecipientInfo   info,
        AlgorithmIdentifier     encAlg,
        InputStream             data)
    {
        super(encAlg, AlgorithmIdentifier.getInstance(info.getKeyEncryptionAlgorithm()), data);
        
        this._info = info;
        this._encAlg = encAlg;
        this._rid = new RecipientId();

        RecipientIdentifier r = info.getRecipientIdentifier();

        try
        {
            if (r.isTagged())
            {
                ASN1OctetString octs = ASN1OctetString.getInstance(r.getId());

                _rid.setSubjectKeyIdentifier(octs.getOctets());
            }
            else
            {
                IssuerAndSerialNumber   iAnds = IssuerAndSerialNumber.getInstance(r.getId());

                ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
                ASN1OutputStream        aOut = new ASN1OutputStream(bOut);

                aOut.writeObject(iAnds.getName());

                _rid.setIssuer(bOut.toByteArray());
                _rid.setSerialNumber(iAnds.getSerialNumber().getValue());
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
    
    /**
     * decrypt the content and return it as a byte array.
     */
    public CMSTypedStream getContentStream(
        Key      key,
        String   prov)
        throws CMSException, NoSuchProviderException
    {
        byte[]  encryptedKey = _info.getEncryptedKey().getOctets();
        String  keyExchangeAlgorithm = getExchangeEncryptionAlgorithmName(_keyEncAlg.getObjectId());
        String  alg = getDataEncryptionAlgorithmName(_encAlg.getObjectId());

        try
        {
            Cipher  keyCipher = Cipher.getInstance(keyExchangeAlgorithm, prov);
            Key     sKey;
            
            try
            {
                keyCipher.init(Cipher.UNWRAP_MODE, key);

                sKey = keyCipher.unwrap(encryptedKey, alg, Cipher.SECRET_KEY);
            }
            catch (GeneralSecurityException e)   // some providers do not support UNWRAP
            {
                keyCipher.init(Cipher.DECRYPT_MODE, key);

                sKey = new SecretKeySpec(keyCipher.doFinal(encryptedKey), alg);
            }
            catch (IllegalStateException e)   // some providers do not support UNWRAP
            {
                keyCipher.init(Cipher.DECRYPT_MODE, key);

                sKey = new SecretKeySpec(keyCipher.doFinal(encryptedKey), alg);
            }
            catch (UnsupportedOperationException e)   // some providers do not support UNWRAP
            {
                keyCipher.init(Cipher.DECRYPT_MODE, key);

                sKey = new SecretKeySpec(keyCipher.doFinal(encryptedKey), alg);
            }

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
