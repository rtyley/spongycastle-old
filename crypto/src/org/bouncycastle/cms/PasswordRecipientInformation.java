package org.bouncycastle.cms;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.cms.PasswordRecipientInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * the RecipientInfo class for a recipient who has been sent a message
 * encrypted using a password.
 */
public class PasswordRecipientInformation
    extends RecipientInformation
{
    private PasswordRecipientInfo info;

    PasswordRecipientInformation(
        PasswordRecipientInfo   info,
        CMSSecureReadable       secureReadable)
    {
        super(info.getKeyEncryptionAlgorithm(), secureReadable);

        this.info = info;
        this.rid = new RecipientId();
    }

    /**
     * return the object identifier for the key derivation algorithm, or null
     * if there is none present.
     *
     * @return OID for key derivation algorithm, if present.
     */
    public String getKeyDerivationAlgOID()
    {
        if (info.getKeyDerivationAlgorithm() != null)
        {
            return info.getKeyDerivationAlgorithm().getObjectId().getId();
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
            if (info.getKeyDerivationAlgorithm() != null)
            {
                DEREncodable params = info.getKeyDerivationAlgorithm().getParameters();
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
            if (info.getKeyDerivationAlgorithm() != null)
            {
                DEREncodable params = info.getKeyDerivationAlgorithm().getParameters();
                if (params != null)
                {
                    AlgorithmParameters algP = AlgorithmParameters.getInstance(info.getKeyDerivationAlgorithm().getObjectId().toString(), provider);

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
            CMSEnvelopedHelper  helper = CMSEnvelopedHelper.INSTANCE;
            AlgorithmIdentifier kekAlg = AlgorithmIdentifier.getInstance(info.getKeyEncryptionAlgorithm());
            ASN1Sequence        kekAlgParams = (ASN1Sequence)kekAlg.getParameters();
            String              kekAlgName = DERObjectIdentifier.getInstance(kekAlgParams.getObjectAt(0)).getId();
            String              wrapAlgName = helper.getRFC3211WrapperName(kekAlgName);

            Cipher keyCipher = helper.createSymmetricCipher(wrapAlgName, prov);
            IvParameterSpec ivSpec = new IvParameterSpec(ASN1OctetString.getInstance(kekAlgParams.getObjectAt(1)).getOctets());
            keyCipher.init(Cipher.UNWRAP_MODE, new SecretKeySpec(((CMSPBEKey)key).getEncoded(kekAlgName), kekAlgName), ivSpec);

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
        catch (InvalidAlgorithmParameterException e)
        {
            throw new CMSException("invalid iv.", e);
        }
    }
}
