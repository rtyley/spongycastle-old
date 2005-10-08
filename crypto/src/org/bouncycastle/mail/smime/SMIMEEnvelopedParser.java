package org.bouncycastle.mail.smime;

import java.io.IOException;
import java.io.InputStream;

import javax.mail.MessagingException;
import javax.mail.Part;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimePart;

import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSException;

/**
 * Stream based containing class for an S/MIME pkcs7-mime encrypted MimePart.
 */
public class SMIMEEnvelopedParser
    extends CMSEnvelopedDataParser
{
    MimePart                message;

    private static InputStream getInputStream(
        Part    bodyPart)
        throws IOException, MessagingException
    {
        return bodyPart.getInputStream();
    }

    public SMIMEEnvelopedParser(
        MimeBodyPart    message) 
        throws IOException, CMSException, MessagingException
    {
        super(getInputStream(message));

        this.message = message;
    }

    public SMIMEEnvelopedParser(
        MimeMessage    message) 
        throws IOException, CMSException, MessagingException
    {
        super(getInputStream(message));

        this.message = message;
    }

    public MimePart getEncryptedContent()
    {
        return message;
    }
}
