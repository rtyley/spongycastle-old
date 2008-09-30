package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEREncodable;
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
import java.security.Provider;
import java.security.AlgorithmParameters;

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
     * return the object identifier for the key derivation algorithm, or null
     * if there is none present.
     *
     * @return OID for key derivation algorithm, if present.
     */
    public String getKeyDerivationAlgOID()
    {
        if (_info.getKeyDerivationAlgorithm() != null)
        {
            return _info.getKeyDerivationAlgorithm().getObjectId().getId();
        }

        return null;
    }

    /**
     * return the ASN.1 encoded key derivation algorithm parameters, or null if
     * there aren't any.
     * @return ASN.1 encoding of key derivation algorithm parameters.
     */
    public byte[] getKeyDerivationAlgParams()
    {
        try
        {
            if (_info.getKeyDerivationAlgorithm() != null)
            {
                DEREncodable params = _info.getKeyDerivationAlgorithm().getParameters();
                if (params != null)
                {
                    return params.getDERObject().getEncoded();
                }
            }

            return null;
        }
        catch (Exception e)
        {
            throw new RuntimeException("exception getting encryption parameters " + e);
        }
    }

    /**
     * return an AlgorithmParameters object representing the parameters to the
     * key derivation algorithm to the recipient.
     *
     * @return AlgorithmParameters object, null if there aren't any.
     */
    public AlgorithmParameters getKeyDerivationAlgParameters(String provider)
        throws NoSuchProviderException
    {
        return getKeyDerivationAlgParameters(CMSUtils.getProvider(provider));
    }
    
   /**
     * return an AlgorithmParameters object representing the parameters to the
     * key derivation algorithm to the recipient.
     *
     * @return AlgorithmParameters object, null if there aren't any.
     */
    public AlgorithmParameters getKeyDerivationAlgParameters(Provider provider)
    {
        try
        {
            if (_info.getKeyDerivationAlgorithm() != null)
            {
                DEREncodable params = _info.getKeyDerivationAlgorithm().getParameters();
                if (params != null)
                {
                    AlgorithmParameters algP = AlgorithmParameters.getInstance(_info.getKeyDerivationAlgorithm().getObjectId().toString(), provider.getName());

                    algP.init(params.getDERObject().getEncoded());

                    return algP;
                }
            }

            return null;
        }
        catch (Exception e)
        {
            throw new RuntimeException("exception getting encryption parameters " + e);
        }
    }

    /**
     * decrypt the content and return an input stream.
     */
    public CMSTypedStream getContentStream(
        Key key,
        String   prov)
        throws CMSException, NoSuchProviderException
    {
        return getContentStream(key, CMSUtils.getProvider(prov));
    }

    /**
     * decrypt the content and return an input stream.
     */
    public CMSTypedStream getContentStream(
        Key key,
        Provider prov)
        throws CMSException
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
