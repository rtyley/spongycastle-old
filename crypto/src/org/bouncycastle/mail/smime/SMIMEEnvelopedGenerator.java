package org.bouncycastle.mail.smime;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;
import javax.mail.MessagingException;
import javax.mail.internet.InternetHeaders;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;

import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.util.encoders.Base64;

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

    private CMSEnvelopedDataGenerator fact;

    static
    {
        MailcapCommandMap mc = (MailcapCommandMap)CommandMap.getDefaultCommandMap();

        mc.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
        mc.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");

        CommandMap.setDefaultCommandMap(mc);
    }

    /**
     * base constructor
     */
    public SMIMEEnvelopedGenerator()
    {
        fact = new CMSEnvelopedDataGenerator();
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
     * if we get here we expect the Mime body part to be well defined.
     */
    private MimeBodyPart make(
        MimeBodyPart    content,
        String          encryptionOID,
        int             keySize,
        String          provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, SMIMEException
    {
        CMSEnvelopedData    envelopedData;

        try
        {
            if (keySize == 0)       // use default
            {
                envelopedData = fact.generate(
                    new CMSProcessableBodyPart(content), encryptionOID, provider);
            }
            else
            {
                envelopedData = fact.generate(
                    new CMSProcessableBodyPart(content), encryptionOID, keySize, provider);
            }
        }
        catch (CMSException e)
        {
            throw new SMIMEException(e.getMessage(), e.getUnderlyingException());
        }

        InternetHeaders sigHeader = new InternetHeaders();

        sigHeader.addHeader("Content-Type", "application/pkcs7-mime; name=\"smime.p7m\"; smime-type=enveloped-data");
        sigHeader.addHeader("Content-Disposition", "attachment; filename=\"smime.p7m\"");
        sigHeader.addHeader("Content-Description", "S/MIME Encrypted Message");

        try
        {
            MimeBodyPart    data;

            if (useBase64)
            {
                sigHeader.addHeader("Content-Transfer-Encoding", "base64");
                data = new MimeBodyPart(sigHeader, Base64.encode(envelopedData.getEncoded()));
            }
            else
            {
                sigHeader.addHeader("Content-Transfer-Encoding", encoding);
                data = new MimeBodyPart(sigHeader, envelopedData.getEncoded());
            }

            return data;
        }
        catch (MessagingException e)
        {
            throw new SMIMEException("exception putting multi-part together.", e);
        }
        catch (IOException e)
        {
            throw new SMIMEException("exception generating encoded content", e);
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
}
