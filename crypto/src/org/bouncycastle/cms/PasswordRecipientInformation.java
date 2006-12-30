package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.cms.PasswordRecipientInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * the RecipientInfo class for a recipient who has been sent a message
 * encrypted using a password.
 */
public class PasswordRecipientInformation
    extends RecipientInformation
{
    private PasswordRecipientInfo _info;
    private AlgorithmIdentifier   _encAlg;

    public PasswordRecipientInformation(
        PasswordRecipientInfo   info,
        AlgorithmIdentifier     encAlg,
        InputStream             data)
    {
        super(encAlg, AlgorithmIdentifier.getInstance(info.getKeyEncryptionAlgorithm()), data);

        this._info = info;
        this._encAlg = encAlg;
        this._rid = new RecipientId();
    }

    /**
     * decrypt the content and return an input stream.
     */
    public CMSTypedStream getContentStream(
        Key key,
        String   prov)
        throws CMSException, NoSuchProviderException
    {
        try
        {
            AlgorithmIdentifier kekAlg = AlgorithmIdentifier.getInstance(_info.getKeyEncryptionAlgorithm());
            ASN1Sequence        kekAlgParams = (ASN1Sequence)kekAlg.getParameters();
            byte[]              encryptedKey = _info.getEncryptedKey().getOctets();
            String              kekAlgName = DERObjectIdentifier.getInstance(kekAlgParams.getObjectAt(0)).getId();
            Cipher keyCipher = Cipher.getInstance(
                                        CMSEnvelopedHelper.INSTANCE.getRFC3211WrapperName(kekAlgName), prov);

            IvParameterSpec ivSpec = new IvParameterSpec(ASN1OctetString.getInstance(kekAlgParams.getObjectAt(1)).getOctets());
            keyCipher.init(Cipher.UNWRAP_MODE, new SecretKeySpec(((CMSPBEKey)key).getEncoded(kekAlgName), kekAlgName), ivSpec);

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
        catch (InvalidAlgorithmParameterException e)
        {
            throw new CMSException("invalid iv.", e);
        }
    }
}
