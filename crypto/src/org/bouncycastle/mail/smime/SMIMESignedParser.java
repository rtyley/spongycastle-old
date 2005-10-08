package org.bouncycastle.mail.smime;

import java.io.IOException;
import java.io.InputStream;

import javax.mail.MessagingException;
import javax.mail.Part;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedStream;

/**
 * general class for handling a pkcs7-signature message.
 * <p>
 * A simple example of usage - note, in the example below the validity of
 * the certificate isn't verified, just the fact that one of the certs 
 * matches the given signer...
 * <p>
 * <pre>
 *  CertStore               certs = s.getCertificates("Collection", "BC");
 *  SignerInformationStore  signers = s.getSignerInfos();
 *  Collection              c = signers.getSigners();
 *  Iterator                it = c.iterator();
 *  
 *  while (it.hasNext())
 *  {
 *      SignerInformation   signer = (SignerInformation)it.next();
 *      Collection          certCollection = certs.getCertificates(signer.getSID());
 *  
 *      Iterator        certIt = certCollection.iterator();
 *      X509Certificate cert = (X509Certificate)certIt.next();
 *  
 *      if (signer.verify(cert.getPublicKey()))
 *      {
 *          verified++;
 *      }   
 *  }
 * </pre>
 * <p>
 * Note: if you are using this class with AS2 or some other protocol
 * that does not use 7bit as the default content transfer encoding you
 * will need to use the constructor that allows you to specify the default
 * content transfer encoding, such as "binary".
 * </p>
 */
public class SMIMESignedParser
    extends CMSSignedDataParser
{
    Object                  message;
    MimeBodyPart            content;

    private static InputStream getInputStream(
        Part    bodyPart)
        throws MessagingException
    {
        try
        {
            if (bodyPart.isMimeType("multipart/signed"))
            {
                throw new MessagingException("attempt to create signed data object from multipart content - use MimeMultipart constructor.");
            }
            
            return bodyPart.getInputStream();
        }
        catch (IOException e)
        {
            throw new MessagingException("can't extract input stream: " + e);
        }
    }

    /**
     * base constructor using a defaultContentTransferEncoding of 7bit
     *
     * @exception MessagingException on an error extracting the signature or
     * otherwise processing the message.
     * @exception CMSException if some other problem occurs.
     */
//    public SMIMESignedParser(
//        MimeMultipart message) 
//        throws IOException, MessagingException, CMSException
//    {
//        super(new CMSTypedStream(message.getBodyPart(0).getInputStream()), getInputStream(message.getBodyPart(1)));
//
//        this.message = message;
//        this.content = (MimeBodyPart)message.getBodyPart(0);
//    }

    /**
     * base constructor with settable contentTransferEncoding
     *
     * @param message the signed message
     * @param defaultContentTransferEncoding new default to use
     * @exception MessagingException on an error extracting the signature or
     * otherwise processing the message.
     * @exception CMSException if some other problem occurs.
     */
//    public SMIMESignedParser(
//        MimeMultipart message,
//        String        defaultContentTransferEncoding) 
//        throws IOException, MessagingException, CMSException
//    {
//        super(new CMSTypedStream(message.getBodyPart(0).getInputStream()), getInputStream(message.getBodyPart(1)));
//
//        this.message = message;
//        this.content = (MimeBodyPart)message.getBodyPart(0);
//    }
    
    /**
     * base constructor for a signed message with encapsulated content.
     *
     * @exception MessagingException on an error extracting the signature or
     * otherwise processing the message.
     * @exception SMIMEException if the body part encapsulated in the message cannot be extracted.
     * @exception CMSException if some other problem occurs.
     */
    public SMIMESignedParser(
        Part message) 
        throws MessagingException, CMSException, SMIMEException
    {
        super(getInputStream(message));

        this.message = message;

        CMSTypedStream  cont = this.getSignedContent();

        if (cont != null)
        {
	        this.content = new MimeBodyPart(cont.getContentStream());
        }
    }

    /**
     * return the content that was signed.
     */
    public MimeBodyPart getContent()
    {
        return content;
    }

    /**
     * Return the content that was signed as a mime message.
     *
     * @param session
     * @return a MimeMessage holding the content.
     * @throws MessagingException
     */
    public MimeMessage getContentAsMimeMessage(Session session)
        throws MessagingException, IOException
    {
        return new MimeMessage(session, getSignedContent().getContentStream());
    }

    /**
     * return the content that was signed - depending on whether this was
     * unencapsulated or not it will return a MimeMultipart or a MimeBodyPart
     */
    public Object getContentWithSignature()
    {
        return message;
    }
}
