package org.bouncycastle.mail.smime;

import java.io.IOException;
import java.util.Enumeration;

import javax.mail.Header;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;

/**
 * super class of the various generators.
 */
public class SMIMEGenerator
{
    protected boolean                     useBase64 = true;
    protected String                      encoding = "base64";  // default sets base64

    /**
     * base constructor
     */
    protected SMIMEGenerator()
    {
    }

    /**
     * set the content-transfer-encoding for the signature.
     */
    public void setContentTransferEncoding(
        String  encoding)
    {
        this.encoding = encoding;
        this.useBase64 = encoding.toLowerCase().equals("base64");
    }

    /**
     * Make sure we have a valid content body part - setting the headers
     * with defaults if neccessary.
     */
    protected MimeBodyPart makeContentBodyPart(
        MimeBodyPart    content)
        throws SMIMEException
    {
        //
        // add the headers to the body part - if they are missing, in
        // the event they have already been set the content settings override
        // any defaults that might be set.
        //
        try
        {
            MimeMessage     msg = new MimeMessage((Session)null);

            Enumeration     e = content.getAllHeaders();

            msg.setDataHandler(content.getDataHandler());

            while (e.hasMoreElements())
            {
                Header  hdr =(Header)e.nextElement();

                msg.setHeader(hdr.getName(), hdr.getValue());
            }

            msg.saveChanges();

            //
            // we do this to make sure at least the default headers are
            // set in the body part.
            //
            e = msg.getAllHeaders();

            while (e.hasMoreElements())
            {
                Header  hdr =(Header)e.nextElement();

                if (hdr.getName().toLowerCase().startsWith("content-"))
                {
                    content.setHeader(hdr.getName(), hdr.getValue());
                }
            }
        }
        catch (MessagingException e)
        {
            throw new SMIMEException("exception saving message state.", e);
        }

        return content;
    }

    /**
     * extract an appropriate body part from the passed in MimeMessage
     */
    protected MimeBodyPart makeContentBodyPart(
        MimeMessage     message)
        throws SMIMEException
    {
        MimeBodyPart    content = new MimeBodyPart();

        //
        // add the headers to the body part.
        //
        try
        {
            
            message.removeHeader("Message-Id");      
            message.removeHeader("Mime-Version");
            
            content.setContent(message.getContent(), message.getContentType());

            Enumeration e = message.getAllHeaders();

            while (e.hasMoreElements())
            {
                Header  hdr =(Header)e.nextElement();

                content.setHeader(hdr.getName(), hdr.getValue());
            }
        }
        catch (MessagingException e)
        {
            throw new SMIMEException("exception saving message state.", e);
        }
        catch (IOException e)
        {
            throw new SMIMEException("exception getting message content.", e);
        }

        return content;
    }
}
