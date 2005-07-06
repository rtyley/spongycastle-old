package org.bouncycastle.mail.smime;

import java.io.IOException;

import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;
import javax.mail.MessagingException;
import javax.mail.internet.InternetHeaders;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;

import org.bouncycastle.cms.CMSCompressedData;
import org.bouncycastle.cms.CMSCompressedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.util.encoders.Base64;

/**
 * General class for generating a pkcs7-mime message.
 *
 * A simple example of usage.
 *
 * <pre>
 *      SMIMECompressedGenerator  fact = new SMIMECompressedGenerator();
 *
 *      fact.addKeyTransRecipient(cert);
 *
 *      MimeBodyPart           smime = fact.generate(content, algorithm, "BC");
 * </pre>
 *
 * <b>Note:<b> Most clients expect the MimeBodyPart to be in a MimeMultipart
 * when it's sent.
 */
public class SMIMECompressedGenerator
    extends SMIMEGenerator
{
    public static final String  ZLIB    = CMSCompressedDataGenerator.ZLIB;

    private CMSCompressedDataGenerator fact;

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
    public SMIMECompressedGenerator()
    {
        fact = new CMSCompressedDataGenerator();
    }

    /**
     * generate an compressed object that contains an SMIME Compressed
     * object using the given provider.
     */
    private MimeBodyPart make(
        MimeBodyPart    content,
        String          compressionOID)
        throws SMIMEException
    {
        CMSCompressedData    compressedData;

        try
        {
            compressedData = fact.generate(
                new CMSProcessableBodyPart(content), compressionOID);
        }
        catch (CMSException e)
        {
            throw new SMIMEException(e.getMessage(), e.getUnderlyingException());
        }

        InternetHeaders sigHeader = new InternetHeaders();

        sigHeader.addHeader("Content-Type", "application/pkcs7-mime; name=\"smime.p7z\"; smime-type=compressed-data");
        sigHeader.addHeader("Content-Disposition", "attachment; filename=\"smime.p7z\"");
        sigHeader.addHeader("Content-Description", "S/MIME Compressed Message");

        try
        {
            MimeBodyPart    data;

            if (useBase64)
            {
                sigHeader.addHeader("Content-Transfer-Encoding", "base64");
                data = new MimeBodyPart(sigHeader, Base64.encode(compressedData.getEncoded()));
            }
            else
            {
                sigHeader.addHeader("Content-Transfer-Encoding", encoding);
                data = new MimeBodyPart(sigHeader, compressedData.getEncoded());
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
     * generate an compressed object that contains an SMIME Compressed
     * object using the given provider from the contents of the passed in
     * message
     */
    public MimeBodyPart generate(
        MimeBodyPart    content,
        String          compressionOID)
        throws SMIMEException
    {
        return make(makeContentBodyPart(content), compressionOID);
    }

    /**
     * generate an compressed object that contains an SMIME Compressed
     * object using the given provider from the contents of the passed in
     * message
     */
    public MimeBodyPart generate(
        MimeMessage     message,
        String          compressionOID)
        throws SMIMEException
    {
        try
        {
            message.saveChanges();      // make sure we're up to date.
        }
        catch (MessagingException e)
        {
            throw new SMIMEException("unable to save message", e);
        }
                        
        return make(makeContentBodyPart(message), compressionOID);
    }
}
