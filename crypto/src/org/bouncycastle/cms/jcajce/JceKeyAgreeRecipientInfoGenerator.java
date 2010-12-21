package org.bouncycastle.cms.jcajce;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.KeyAgreeRecipientIdentifier;
import org.bouncycastle.asn1.cms.RecipientEncryptedKey;
import org.bouncycastle.asn1.cms.ecc.MQVuserKeyingMaterial;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyAgreeRecipientInfoGenerator;
import org.bouncycastle.jcajce.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.NamedJcaJceHelper;
import org.bouncycastle.jcajce.ProviderJcaJceHelper;
import org.bouncycastle.jce.spec.MQVPrivateKeySpec;
import org.bouncycastle.jce.spec.MQVPublicKeySpec;
import org.bouncycastle.operator.GenericKey;

public class JceKeyAgreeRecipientInfoGenerator
    extends KeyAgreeRecipientInfoGenerator
{
    private List recipientCerts;
    private PublicKey senderPublicKey;
    private PrivateKey senderPrivateKey;

    private EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceHelper());
    private SecureRandom random;
    private KeyPair ephemeralKP;

    public JceKeyAgreeRecipientInfoGenerator(ASN1ObjectIdentifier keyAgreementOID, PrivateKey senderPrivateKey, PublicKey senderPublicKey, ASN1ObjectIdentifier keyEncryptionOID, List recipientCerts)
        throws CMSException
    {
        super(keyAgreementOID, SubjectPublicKeyInfo.getInstance(senderPublicKey.getEncoded()), keyEncryptionOID);

        this.senderPublicKey = senderPublicKey;
        this.senderPrivateKey = senderPrivateKey;
        this.recipientCerts = recipientCerts;
    }

    public JceKeyAgreeRecipientInfoGenerator(ASN1ObjectIdentifier keyAgreementOID, PrivateKey senderPrivateKey, PublicKey senderPublicKey, ASN1ObjectIdentifier keyEncryptionOID, X509Certificate recipientCert)
        throws CMSException
    {
        this(keyAgreementOID, senderPrivateKey, senderPublicKey, keyEncryptionOID,  Collections.singletonList(recipientCert));
    }

    public JceKeyAgreeRecipientInfoGenerator setProvider(Provider provider)
    {
        this.helper = new EnvelopedDataHelper(new ProviderJcaJceHelper(provider));

        return this;
    }

    public JceKeyAgreeRecipientInfoGenerator setProvider(String providerName)
    {
        this.helper = new EnvelopedDataHelper(new NamedJcaJceHelper(providerName));

        return this;
    }

    public JceKeyAgreeRecipientInfoGenerator setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public ASN1Sequence generateRecipientEncryptedKeys(AlgorithmIdentifier keyAgreeAlgorithm, AlgorithmIdentifier keyEncryptionAlgorithm, GenericKey contentEncryptionKey)
        throws CMSException
    {
        init(keyAgreeAlgorithm.getAlgorithm());

        PrivateKey senderPrivateKey = this.senderPrivateKey;

        ASN1ObjectIdentifier keyAgreementOID = keyAgreeAlgorithm.getAlgorithm();

        if (keyAgreementOID.getId().equals(CMSEnvelopedGenerator.ECMQV_SHA1KDF))
        {           
            senderPrivateKey = new MQVPrivateKeySpec(
                senderPrivateKey, ephemeralKP.getPrivate(), ephemeralKP.getPublic());
        }

        ASN1EncodableVector recipientEncryptedKeys = new ASN1EncodableVector();
        Iterator it = recipientCerts.iterator();
        while (it.hasNext())
        {
            X509Certificate recipientCert = (X509Certificate)it.next();
            KeyAgreeRecipientIdentifier karid;

            try
            {
            // TODO Should there be a SubjectKeyIdentifier-based alternative?
                karid = new KeyAgreeRecipientIdentifier(
                    CMSUtils.getIssuerAndSerialNumber(recipientCert));
            }
            catch (CertificateEncodingException e)
            {
                throw new CMSException("cannot parse recipient certificate: " + e.getMessage(), e);
            }

            PublicKey recipientPublicKey = recipientCert.getPublicKey();

            if (keyAgreementOID.getId().equals(CMSEnvelopedGenerator.ECMQV_SHA1KDF))
            {
                recipientPublicKey = new MQVPublicKeySpec(recipientPublicKey, recipientPublicKey);
            }

            try
            {
                // Use key agreement to choose a wrap key for this recipient
                KeyAgreement keyAgreement = helper.createKeyAgreement(keyAgreementOID);
                keyAgreement.init(senderPrivateKey, random);
                keyAgreement.doPhase(recipientPublicKey, true);
                SecretKey keyEncryptionKey = keyAgreement.generateSecret(keyEncryptionAlgorithm.getAlgorithm().getId());

                // Wrap the content encryption key with the agreement key
                Cipher keyEncryptionCipher = helper.createCipher(keyEncryptionAlgorithm.getAlgorithm());

                keyEncryptionCipher.init(Cipher.WRAP_MODE, keyEncryptionKey, random);

                byte[] encryptedKeyBytes = keyEncryptionCipher.wrap(CMSUtils.getJceKey(contentEncryptionKey));

                ASN1OctetString encryptedKey = new DEROctetString(encryptedKeyBytes);

                recipientEncryptedKeys.add(new RecipientEncryptedKey(karid, encryptedKey));
            }
            catch (GeneralSecurityException e)
            {
                throw new CMSException("cannot perform agreement step: " + e.getMessage(), e);
            }
        }

        return new DERSequence(recipientEncryptedKeys);
    }

    protected ASN1Encodable getUserKeyingMaterial(AlgorithmIdentifier keyAgreeAlg)
        throws CMSException
    {
        init(keyAgreeAlg.getAlgorithm());

        if (ephemeralKP != null)
        {
            return new MQVuserKeyingMaterial(
                        createOriginatorPublicKey(SubjectPublicKeyInfo.getInstance(ephemeralKP.getPublic().getEncoded())), null);
        }

        return null;
    }

    private void init(ASN1ObjectIdentifier keyAgreementOID)
        throws CMSException
    {
        if (random == null)
        {
            random = new SecureRandom();
        }

        if (keyAgreementOID.equals(CMSAlgorithm.ECMQV_SHA1KDF))
        {
            if (ephemeralKP == null)
            {
                try
                {
                    ECParameterSpec ecParamSpec = ((ECPublicKey)senderPublicKey).getParams();

                    KeyPairGenerator ephemKPG = helper.createKeyPairGenerator(keyAgreementOID);

                    ephemKPG.initialize(ecParamSpec, random);

                    ephemeralKP = ephemKPG.generateKeyPair();
                }
                catch (InvalidAlgorithmParameterException e)
                {
                    throw new CMSException(
                        "cannot determine MQV ephemeral key pair parameters from public key: " + e);
                }
            }
        }
    }
}