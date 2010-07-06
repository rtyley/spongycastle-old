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
import javax.crypto.spec.SecretKeySpec;

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
import org.bouncycastle.cms.CMSEnvelopedGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyAgreeRecipientInfoGenerator;
import org.bouncycastle.jce.spec.MQVPrivateKeySpec;
import org.bouncycastle.jce.spec.MQVPublicKeySpec;

public class JceKeyAgreeRecipientInfoGenerator
    extends KeyAgreeRecipientInfoGenerator
{
    private List recipientCerts;
    private PublicKey senderPublicKey;
    private PrivateKey senderPrivateKey;

    private EnvelopedDataHelper helper = new DefaultEnvelopedDataHelper();
    private SecureRandom random;
    private KeyPair ephemeralKP;

    public JceKeyAgreeRecipientInfoGenerator(ASN1ObjectIdentifier keyAgreementOID, PrivateKey senderPrivateKey, PublicKey senderPublicKey, ASN1ObjectIdentifier keyEncryptionOID, List recipientCerts, SecureRandom random)
        throws CMSException
    {
        super(keyAgreementOID, SubjectPublicKeyInfo.getInstance(senderPublicKey.getEncoded()), keyEncryptionOID);

        this.senderPublicKey = senderPublicKey;
        this.senderPrivateKey = senderPrivateKey;
        this.recipientCerts = recipientCerts;
        this.random = random;

        if (keyAgreementOID.getId().equals(CMSEnvelopedGenerator.ECMQV_SHA1KDF))
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

    public JceKeyAgreeRecipientInfoGenerator(ASN1ObjectIdentifier keyAgreementOID, PrivateKey senderPrivateKey, PublicKey senderPublicKey, ASN1ObjectIdentifier keyEncryptionOID, X509Certificate recipientCert, SecureRandom random)
        throws CMSException
    {
        this(keyAgreementOID, senderPrivateKey, senderPublicKey, keyEncryptionOID,  Collections.singletonList(recipientCert), random);
    }

    public JceKeyAgreeRecipientInfoGenerator(ASN1ObjectIdentifier keyAgreementOID, PrivateKey senderPrivateKey, PublicKey senderPublicKey, ASN1ObjectIdentifier keyEncryptionOID, List recipientCerts)
        throws CMSException
    {
         this(keyAgreementOID, senderPrivateKey, senderPublicKey, keyEncryptionOID, recipientCerts, new SecureRandom());
    }

    public JceKeyAgreeRecipientInfoGenerator(ASN1ObjectIdentifier keyAgreementOID, PrivateKey senderPrivateKey, PublicKey senderPublicKey, ASN1ObjectIdentifier keyEncryptionOID, X509Certificate recipientCert)
        throws CMSException
    {
        this(keyAgreementOID, senderPrivateKey, senderPublicKey, keyEncryptionOID, recipientCert, new SecureRandom());
    }

    public JceKeyAgreeRecipientInfoGenerator setProvider(Provider provider)
    {
        this.helper = new ProviderEnvelopedDataHelper(provider);

        return this;
    }

    public JceKeyAgreeRecipientInfoGenerator setProvider(String providerName)
    {
        this.helper = new NamedEnvelopedDataHelper(providerName);

        return this;
    }

    public ASN1Sequence generateRecipientEncryptedKeys(AlgorithmIdentifier keyAgreeAlgorithm, AlgorithmIdentifier keyEncryptionAlgorithm, byte[] contentEncryptionKey)
        throws CMSException
    {
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

                byte[] encryptedKeyBytes = keyEncryptionCipher.wrap(new SecretKeySpec(contentEncryptionKey, "WRAP"));

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

    protected ASN1Encodable getUserKeyingMaterial()
    {
        if (ephemeralKP != null)
        {
            return new MQVuserKeyingMaterial(
                        createOriginatorPublicKey(SubjectPublicKeyInfo.getInstance(ephemeralKP.getPublic().getEncoded())), null);
        }

        return null;
    }
}