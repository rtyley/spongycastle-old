package org.bouncycastle.mail.smime;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSException;

import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;
import javax.crypto.SecretKey;
import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import java.io.IOException;
import java.io.OutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Provider;
import java.security.cert.X509Certificate;

/**
 * General class for generating a pkcs7-mime message.
 *
 * A simple example of usage.
 *
 * <pre>
 *      SMIMEEnvelopedGenerator  fact = new SMIMEEnvelopedGenerator();
 *
 *      fact.addKeyTransRecipient(cert);
 *
 *      MimeBodyPart           smime = fact.generate(content, algorithm, "BC");
 * </pre>
 *
 * <b>Note:<b> Most clients expect the MimeBodyPart to be in a MimeMultipart
 * when it's sent.
 */
public class SMIMEEnvelopedGenerator
    extends SMIMEGenerator
{
    public static final String  DES_EDE3_CBC    = CMSEnvelopedDataGenerator.DES_EDE3_CBC;
    public static final String  RC2_CBC         = CMSEnvelopedDataGenerator.RC2_CBC;
    public static final String  IDEA_CBC        = CMSEnvelopedDataGenerator.IDEA_CBC;
    public static final String  CAST5_CBC       = CMSEnvelopedDataGenerator.CAST5_CBC;

    public static final String  AES128_CBC      = CMSEnvelopedDataGenerator.AES128_CBC;
    public static final String  AES192_CBC      = CMSEnvelopedDataGenerator.AES192_CBC;
    public static final String  AES256_CBC      = CMSEnvelopedDataGenerator.AES256_CBC;

    public static final String  CAMELLIA128_CBC = CMSEnvelopedDataGenerator.CAMELLIA128_CBC;
    public static final String  CAMELLIA192_CBC = CMSEnvelopedDataGenerator.CAMELLIA192_CBC;
    public static final String  CAMELLIA256_CBC = CMSEnvelopedDataGenerator.CAMELLIA256_CBC;

    public static final String  SEED_CBC        = CMSEnvelopedDataGenerator.SEED_CBC;

    public static final String  DES_EDE3_WRAP   = CMSEnvelopedDataGenerator.DES_EDE3_WRAP;
    public static final String  AES128_WRAP     = CMSEnvelopedDataGenerator.AES128_WRAP;
    public static final String  AES256_WRAP     = CMSEnvelopedDataGenerator.AES256_WRAP;
    public static final String  CAMELLIA128_WRAP = CMSEnvelopedDataGenerator.CAMELLIA128_WRAP;
    public static final String  CAMELLIA192_WRAP = CMSEnvelopedDataGenerator.CAMELLIA192_WRAP;
    public static final String  CAMELLIA256_WRAP = CMSEnvelopedDataGenerator.CAMELLIA256_WRAP;
    public static final String  SEED_WRAP       = CMSEnvelopedDataGenerator.SEED_WRAP;
    
    public static final String  ECDH_SHA1KDF    = CMSEnvelopedDataGenerator.ECDH_SHA1KDF;

    private static final String ENCRYPTED_CONTENT_TYPE = "application/pkcs7-mime; name=\"smime.p7m\"; smime-type=enveloped-data";
    
    private EnvelopedGenerator fact;

    static
    {
        CommandMap.setDefaultCommandMap(addCommands(CommandMap.getDefaultCommandMap()));
    }

    private static MailcapCommandMap addCommands(CommandMap cm)
    {
        MailcapCommandMap mc = (MailcapCommandMap)cm;

        mc.addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
        mc.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
        mc.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
        mc.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
        mc.addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");

        return mc;
    }

    /**
     * base constructor
     */
    public SMIMEEnvelopedGenerator()
    {
        fact = new EnvelopedGenerator();
    }

    /**
     * add a recipient.
     */
    public void addKeyTransRecipient(
        X509Certificate cert)
        throws IllegalArgumentException
    {
        fact.addKeyTransRecipient(cert);
    }

    /**
     * add a recipient - note: this will only work on V3 and later clients.
     *
     * @param key the recipient's public key
     * @param subKeyId the subject key id for the recipient's public key
     */
    public void addKeyTransRecipient(
        PublicKey   key,
        byte[]      subKeyId)
        throws IllegalArgumentException
    {
        fact.addKeyTransRecipient(key, subKeyId);
    }

    /**
     * add a KEK recipient.
     */
    public void addKEKRecipient(
        SecretKey   key,
        byte[]      keyIdentifier)
        throws IllegalArgumentException
    {
        fact.addKEKRecipient(key, keyIdentifier);
    }

    /**
     * Add a key agreement based recipient.
     *
     * @param senderPrivateKey private key to initialise sender side of agreement with.
     * @param senderPublicKey sender public key to include with message.
     * @param recipientCert recipient's public key certificate.
     * @param cekWrapAlgorithm OID for key wrapping algorithm to use.
     * @param provider provider to use for the agreement calculation.
     */
    public void addKeyAgreementRecipient(
        String           agreementAlgorithm,
        PrivateKey       senderPrivateKey,
        PublicKey        senderPublicKey,
        X509Certificate  recipientCert,
        String           cekWrapAlgorithm,
        String           provider)
        throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException
    {
        fact.addKeyAgreementRecipient(agreementAlgorithm, senderPrivateKey, senderPublicKey, recipientCert, cekWrapAlgorithm, provider);
    }

    /**
     * Add a key agreement based recipient.
     *
     * @param senderPrivateKey private key to initialise sender side of agreement with.
     * @param senderPublicKey sender public key to include with message.
     * @param recipientCert recipient's public key certificate.
     * @param cekWrapAlgorithm OID for key wrapping algorithm to use.
     * @param provider provider to use for the agreement calculation.
     */
    public void addKeyAgreementRecipient(
        String           agreementAlgorithm,
        PrivateKey       senderPrivateKey,
        PublicKey        senderPublicKey,
        X509Certificate  recipientCert,
        String           cekWrapAlgorithm,
        Provider         provider)
        throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException
    {
        fact.addKeyAgreementRecipient(agreementAlgorithm, senderPrivateKey, senderPublicKey, recipientCert, cekWrapAlgorithm, provider);
    }

    /**
     * Use a BER Set to store the recipient information
     */
    public void setBerEncodeRecipients(
        boolean berEncodeRecipientSet)
    {
        fact.setBEREncodeRecipients(berEncodeRecipientSet);
    }
    
    /**
     * if we get here we expect the Mime body part to be well defined.
     */
    private MimeBodyPart make(
        MimeBodyPart    content,
        String          encryptionOID,
        int             keySize,
        Provider        provider)
        throws NoSuchAlgorithmException, SMIMEException
    {
        //
        // check the base algorithm and provider is available
        //
        createSymmetricKeyGenerator(encryptionOID, provider);
                
        try
        {  
            MimeBodyPart data = new MimeBodyPart();
        
            data.setContent(new ContentEncryptor(content, encryptionOID, keySize, provider), ENCRYPTED_CONTENT_TYPE);
            data.addHeader("Content-Type", ENCRYPTED_CONTENT_TYPE);
            data.addHeader("Content-Disposition", "attachment; filename=\"smime.p7m\"");
            data.addHeader("Content-Description", "S/MIME Encrypted Message");
            data.addHeader("Content-Transfer-Encoding", encoding);
    
            return data;
        }
        catch (MessagingException e)
        {
            throw new SMIMEException("exception putting multi-part together.", e);
        }
    }

    /**
     * generate an enveloped object that contains an SMIME Enveloped
     * object using the given provider.
     */
    public MimeBodyPart generate(
        MimeBodyPart    content,
        String          encryptionOID,
        String          provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, SMIMEException
    {
        return make(makeContentBodyPart(content), encryptionOID, 0, SMIMEUtil.getProvider(provider));
    }

    /**
     * generate an enveloped object that contains an SMIME Enveloped
     * object using the given provider.
     */
    public MimeBodyPart generate(
        MimeBodyPart    content,
        String          encryptionOID,
        Provider        provider)
        throws NoSuchAlgorithmException, SMIMEException
    {
        return make(makeContentBodyPart(content), encryptionOID, 0, provider);
    }

    /**
     * generate an enveloped object that contains an SMIME Enveloped
     * object using the given provider from the contents of the passed in
     * message
     */
    public MimeBodyPart generate(
        MimeMessage     message,
        String          encryptionOID,
        String          provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, SMIMEException
    {
        return generate(message, encryptionOID, SMIMEUtil.getProvider(provider));
    }

    /**
     * generate an enveloped object that contains an SMIME Enveloped
     * object using the given provider from the contents of the passed in
     * message
     */
    public MimeBodyPart generate(
        MimeMessage     message,
        String          encryptionOID,
        Provider        provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, SMIMEException
    {
        try
        {
            message.saveChanges();      // make sure we're up to date.
        }
        catch (MessagingException e)
        {
            throw new SMIMEException("unable to save message", e);
        }
                        
        return make(makeContentBodyPart(message), encryptionOID, 0, provider);
    }

    /**
     * generate an enveloped object that contains an SMIME Enveloped
     * object using the given provider. The size of the encryption key
     * is determined by keysize.
     */
    public MimeBodyPart generate(
        MimeBodyPart    content,
        String          encryptionOID,
        int             keySize,
        String          provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, SMIMEException
    {
        return generate(content, encryptionOID, keySize, SMIMEUtil.getProvider(provider));
    }

    /**
     * generate an enveloped object that contains an SMIME Enveloped
     * object using the given provider. The size of the encryption key
     * is determined by keysize.
     */
    public MimeBodyPart generate(
        MimeBodyPart    content,
        String          encryptionOID,
        int             keySize,
        Provider        provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, SMIMEException
    {
        return make(makeContentBodyPart(content), encryptionOID, keySize, provider);
    }

    /**
     * generate an enveloped object that contains an SMIME Enveloped
     * object using the given provider from the contents of the passed in
     * message. The size of the encryption key used to protect the message
     * is determined by keysize.
     */
    public MimeBodyPart generate(
        MimeMessage     message,
        String          encryptionOID,
        int             keySize,
        String          provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, SMIMEException
    {
        return generate(message, encryptionOID, keySize, SMIMEUtil.getProvider(provider));
    }

    /**
     * generate an enveloped object that contains an SMIME Enveloped
     * object using the given provider from the contents of the passed in
     * message. The size of the encryption key used to protect the message
     * is determined by keysize.
     */
    public MimeBodyPart generate(
        MimeMessage     message,
        String          encryptionOID,
        int             keySize,
        Provider        provider)
        throws NoSuchAlgorithmException, SMIMEException
    {
        try
        {
            message.saveChanges();      // make sure we're up to date.
        }
        catch (MessagingException e)
        {
            throw new SMIMEException("unable to save message", e);
        }
                        
        return make(makeContentBodyPart(message), encryptionOID, keySize, provider);
    }
    
    private class ContentEncryptor
        implements SMIMEStreamingProcessor
    {
        private final MimeBodyPart _content;
        private final String _encryptionOid;
        private final int    _keySize;
        private final Provider _provider;
        
        private boolean _firstTime = true;
        
        ContentEncryptor(
            MimeBodyPart content,
            String       encryptionOid,
            int          keySize,
            Provider     provider)
        {
            _content = content;
            _encryptionOid = encryptionOid;
            _keySize = keySize;
            _provider = provider;
        }
    
        public void write(OutputStream out)
            throws IOException
        {
            OutputStream encrypted;
            
            try
            {
                if (_firstTime)
                {
                    if (_keySize == 0)  // use the default
                    {
                        encrypted = fact.open(out, _encryptionOid, _provider);
                    }
                    else
                    {
                        encrypted = fact.open(out, _encryptionOid, _keySize, _provider);
                    }
                    
                    _firstTime = false;
                }
                else
                {
                    encrypted = fact.regenerate(out, _provider);
                }

                _content.getDataHandler().setCommandMap(addCommands(CommandMap.getDefaultCommandMap()));
                
                _content.writeTo(encrypted);
                
                encrypted.close();
            }
            catch (MessagingException e)
            {
                throw new WrappingIOException(e.toString(), e);
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new WrappingIOException(e.toString(), e);
            }
            catch (NoSuchProviderException e)
            {
                throw new WrappingIOException(e.toString(), e);
            }
            catch (CMSException e)
            {
                throw new WrappingIOException(e.toString(), e);
            }
        }
    }
    
    private class EnvelopedGenerator
        extends CMSEnvelopedDataStreamGenerator
    {
        private String _encryptionOID;
        private SecretKey _encKey;
        private AlgorithmParameters _params;
        private ASN1EncodableVector _recipientInfos;

        protected OutputStream open(
            OutputStream        out,
            String              encryptionOID,
            SecretKey           encKey,
            AlgorithmParameters params,
            ASN1EncodableVector recepientInfos,
            Provider            provider)
            throws NoSuchAlgorithmException, CMSException
        {
            _encryptionOID = encryptionOID;
            _encKey = encKey;
            _params = params;
            _recipientInfos = recepientInfos;

            return super.open(out, encryptionOID, encKey, params, recepientInfos, provider);
        }

        OutputStream regenerate(
            OutputStream out,
            Provider     provider)
            throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
        {
            return super.open(out, _encryptionOID, _encKey, _params, _recipientInfos, provider);
        }
    }

    private static class WrappingIOException
        extends IOException
    {
        private Throwable cause;

        WrappingIOException(String msg, Throwable cause)
        {
            super(msg);

            this.cause = cause;
        }

        public Throwable getCause()
        {
            return cause;
        }
    }
}
