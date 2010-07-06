package org.bouncycastle.cms.jcajce;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyTransRecipientInfoGenerator;

public class JceKeyTransRecipientInfoGenerator
    extends KeyTransRecipientInfoGenerator
{
    private final PublicKey      recipientPublicKey;

    private EnvelopedDataHelper helper = new DefaultEnvelopedDataHelper();
    private SecureRandom random;

    public JceKeyTransRecipientInfoGenerator(X509Certificate recipientCert)
        throws CertificateEncodingException
    {
        super(CMSUtils.getTBSCertificateStructure(recipientCert));

        this.recipientPublicKey = recipientCert.getPublicKey();
    }

    public JceKeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, PublicKey recipientPublicKey)
    {
        super(SubjectPublicKeyInfo.getInstance(recipientPublicKey.getEncoded()), subjectKeyIdentifier);

        this.recipientPublicKey = recipientPublicKey;
    }

    public JceKeyTransRecipientInfoGenerator setProvider(Provider provider)
    {
        this.helper = new ProviderEnvelopedDataHelper(provider);

        return this;
    }

    public JceKeyTransRecipientInfoGenerator setProvider(String providerName)
    {
        this.helper = new NamedEnvelopedDataHelper(providerName);

        return this;
    }

    public JceKeyTransRecipientInfoGenerator setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public byte[] generateEncryptedBytes(AlgorithmIdentifier keyEncryptionAlgorithm, byte[] contentEncryptionKey)
        throws CMSException
    {
        Cipher keyEncryptionCipher = helper.createCipher(keyEncryptionAlgorithm.getAlgorithm());
        byte[] encryptedKeyBytes = null;

        try
        {
            keyEncryptionCipher.init(Cipher.WRAP_MODE, recipientPublicKey, random);
            encryptedKeyBytes = keyEncryptionCipher.wrap(new SecretKeySpec(contentEncryptionKey, "WRAP"));
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

        // some providers do not support WRAP (this appears to be only for asymmetric algorithms)
        if (encryptedKeyBytes == null)
        {
            try
            {
                keyEncryptionCipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey, random);
                encryptedKeyBytes = keyEncryptionCipher.doFinal(contentEncryptionKey);
            }
            catch (GeneralSecurityException e)
            {
                throw new CMSException("unable to encrypt contents key", e);
            }
        }

        return encryptedKeyBytes;
    }
}