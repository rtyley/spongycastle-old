package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.KeyAgreeRecipientInfo;
import org.bouncycastle.asn1.cms.OriginatorPublicKey;
import org.bouncycastle.asn1.cms.RecipientEncryptedKey;
//import org.bouncycastle.asn1.cms.ecc.MQVuserKeyingMaterial;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 * the RecipientInfo class for a recipient who has been sent a message
 * encrypted using key agreement.
 */
public class KeyAgreeRecipientInformation
    extends RecipientInformation
{
    private KeyAgreeRecipientInfo info;
    private ASN1OctetString       _encryptedKey;

    public KeyAgreeRecipientInformation(
        KeyAgreeRecipientInfo info,
        AlgorithmIdentifier   encAlg,
        InputStream data)
    {
        this(info, encAlg, null, data);
    }

    public KeyAgreeRecipientInformation(
        KeyAgreeRecipientInfo info,
        AlgorithmIdentifier   encAlg,
        AlgorithmIdentifier   macAlg,
        InputStream data)
    {
        super(encAlg, macAlg, AlgorithmIdentifier.getInstance(info.getKeyEncryptionAlgorithm()), data);

        this.info = info;

        try
        {
            ASN1Sequence s = this.info.getRecipientEncryptedKeys();

            // TODO Handle the case of more than one encrypted key
            RecipientEncryptedKey id = RecipientEncryptedKey.getInstance(
                    s.getObjectAt(0));

            // TODO Add support for RecipientKeyIdentifer option
            IssuerAndSerialNumber iAnds = id.getIdentifier().getIssuerAndSerialNumber();

            rid = new RecipientId();
            rid.setIssuer(iAnds.getName().getEncoded());
            rid.setSerialNumber(iAnds.getSerialNumber().getValue());

            _encryptedKey = id.getEncryptedKey();
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("invalid rid in KeyAgreeRecipientInformation");
        }
    }

    private PublicKey getSenderPublicKey(Key receiverPrivateKey,
        OriginatorPublicKey originatorPublicKey, Provider prov)
        throws GeneralSecurityException, IOException
    {
        PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(
            ASN1Object.fromByteArray(receiverPrivateKey.getEncoded()));

        SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo(
            privInfo.getAlgorithmId(),
            originatorPublicKey.getPublicKey().getBytes());
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubInfo.getEncoded());
        KeyFactory fact = KeyFactory.getInstance(keyEncAlg.getObjectId().getId(), prov);
        return fact.generatePublic(pubSpec);
    }

    private SecretKey calculateAgreedWrapKey(String wrapAlg,
        PublicKey senderPublicKey, Key receiverPrivateKey, Provider prov)
        throws GeneralSecurityException, IOException
    {
        String agreeAlg = keyEncAlg.getObjectId().getId();

        KeyAgreement agreement = KeyAgreement.getInstance(agreeAlg, prov);
        agreement.init(receiverPrivateKey);

        // TODO ECMQV 1-pass key agreement
//        if (agreeAlg.equals(CMSEnvelopedGenerator.ECMQV_SHA1KDF))
//        {
//            byte[] ukmEncoding = info.getUserKeyingMaterial().getOctets();
//            MQVuserKeyingMaterial ukm = MQVuserKeyingMaterial.getInstance(
//                ASN1Object.fromByteArray(ukmEncoding));
//
//            PublicKey ephemeralKey = getSenderPublicKey(receiverPrivateKey,
//                ukm.getEphemeralPublicKey(), prov);
//
//            senderPublicKey = new StaticEphemeralPublicKeySpec(senderPublicKey, ephemeralKey);
//        }

        agreement.doPhase(senderPublicKey, true);
        return agreement.generateSecret(wrapAlg);
    }

    private Key unwrapSessionKey(String wrapAlg, SecretKey agreedKey,
        Provider prov)
        throws GeneralSecurityException
    {
        AlgorithmIdentifier aid = encAlg;
        if (aid == null)
        {
            aid = macAlg;
        }
        
        String alg = aid.getObjectId().getId();
        byte[] encryptedKey = _encryptedKey.getOctets();

        // TODO Should we try alternate ways of unwrapping?
        //   (see KeyTransRecipientInformation.getSessionKey)
        Cipher keyCipher = Cipher.getInstance(wrapAlg, prov);
        keyCipher.init(Cipher.UNWRAP_MODE, agreedKey);
        return keyCipher.unwrap(encryptedKey, alg, Cipher.SECRET_KEY);
    }

    protected Key getSessionKey(Key receiverPrivateKey, Provider prov)
        throws CMSException
    {
        try
        {
            String wrapAlg = DERObjectIdentifier.getInstance(
                ASN1Sequence.getInstance(keyEncAlg.getParameters()).getObjectAt(0)).getId();

            PublicKey senderPublicKey = getSenderPublicKey(receiverPrivateKey,
                info.getOriginator().getOriginatorKey(), prov);

            SecretKey agreedWrapKey = calculateAgreedWrapKey(wrapAlg,
                senderPublicKey, receiverPrivateKey, prov);

            return unwrapSessionKey(wrapAlg, agreedWrapKey, prov);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new CMSException("can't find algorithm.", e);
        }
        catch (InvalidKeyException e)
        {
            throw new CMSException("key invalid in message.", e);
        }
        catch (InvalidKeySpecException e)
        {
            throw new CMSException("originator key spec invalid.", e);
        }
        catch (NoSuchPaddingException e)
        {
            throw new CMSException("required padding not supported.", e);
        }
        catch (Exception e)
        {
            throw new CMSException("originator key invalid.", e);
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
