package org.bouncycastle.mail.smime;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateParsingException;

import javax.mail.MessagingException;
import javax.mail.Part;
import javax.mail.internet.MimeBodyPart;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.mail.smime.util.FileBackedMimeBodyPart;

public class SMIMEUtil
{
    static boolean isCanonicalisationRequired(
        Part   bodyPart,
        String defaultContentTransferEncoding) 
        throws MessagingException
    {
        if (bodyPart instanceof MimeBodyPart)
        {
            MimeBodyPart    mimePart = (MimeBodyPart)bodyPart;
            String[]        cte = mimePart.getHeader("Content-Transfer-Encoding");
            String          contentTransferEncoding;

            if (cte == null)
            {
                contentTransferEncoding = defaultContentTransferEncoding;
            }
            else
            {
                contentTransferEncoding = cte[0];
            }
            
            return !contentTransferEncoding.equalsIgnoreCase("binary");
        }
        else
        {
            return !defaultContentTransferEncoding.equalsIgnoreCase("binary");
        }
    }
    
    /**
     * return the MimeBodyPart described in the raw bytes provided in content
     */
    public static MimeBodyPart toMimeBodyPart(
        byte[]    content)
        throws SMIMEException
    {
        return toMimeBodyPart(new ByteArrayInputStream(content));
    }
    
    /**
     * return the MimeBodyPart described in the input stream content
     */
    public static MimeBodyPart toMimeBodyPart(
        InputStream    content)
        throws SMIMEException
    {
        try
        {
            return new MimeBodyPart(content);
        }
        catch (MessagingException e)
        {
            throw new SMIMEException("exception creating body part.", e);
        }
    }
    
    /**
     * return a file backed MimeBodyPart described in {@link CMSTypedStream} content. 
     * </p>
     */
    public static FileBackedMimeBodyPart toMimeBodyPart(
        CMSTypedStream    content)
        throws SMIMEException
    {
        try
        {
            return toMimeBodyPart(content, File.createTempFile("bcMail", ".mime"));
        }
        catch (IOException e)
        {
            throw new SMIMEException("IOException creating tmp file:" + e.getMessage());
        }
    }
    
    /**
     * Return a file based MimeBodyPart represented by content and backed
     * by the file represented by file.
     * 
     * @param content content stream containing body part.
     * @param file file to store the decoded body part in.
     * @return the decoded body part.
     * @throws SMIMEException
     */
    public static FileBackedMimeBodyPart toMimeBodyPart(
        CMSTypedStream    content,
        File              file)
        throws SMIMEException
    {
        try
        {
            saveContentToFile(content, file);
            
            return new FileBackedMimeBodyPart(file);
        }
        catch (IOException e)
        {
            throw new SMIMEException("can't save content to file: " + e, e);
        }
        catch (MessagingException e)
        {
            throw new SMIMEException("can't create part: " + e, e);
        }
    }

    private static void saveContentToFile(
        CMSTypedStream    content,
        File tmp) 
        throws FileNotFoundException, IOException
    {
        OutputStream out = new FileOutputStream(tmp);
        InputStream  in = content.getContentStream();
        
        byte[] buf = new byte[10000];
        int    len;
        
        while ((len = in.read(buf, 0, buf.length)) > 0)
        {
            out.write(buf, 0, len);
        }
        
        out.close();
        in.close();
    }
    
    /**
     * Return a CMS IssuerAndSerialNumber structure for the passed in X.509 certificate.
     * 
     * @param cert the X.509 certificate to get the issuer and serial number for.
     * @return an IssuerAndSerialNumber structure representing the certificate.
     */
    public static IssuerAndSerialNumber createIssuerAndSerialNumberFor(
        X509Certificate cert)
        throws CertificateParsingException
    {
        try
        {
            return new IssuerAndSerialNumber(PrincipalUtil.getIssuerX509Principal(cert), cert.getSerialNumber());        
        }
        catch (Exception e)
        {
            throw new CertificateParsingException("exception extracting issuer and serial number: " + e);
        }
    }
}
