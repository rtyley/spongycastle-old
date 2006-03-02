package org.bouncycastle.mail.smime;

import java.io.ByteArrayInputStream;
import java.io.File;
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
import org.bouncycastle.mail.smime.util.SharedFileInputStream;

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
     * return the MimeBodyPart described in {@link CMSTypedStream} content. 
     * <p>
     * <b>Note</b>: this requires the creation of a temporary file so the resulting object
     * is designed to be single use. Once you have called the <code>writeTo()</code> method 
     * on the body part the file will be deleted.
     * </p>
     */
    public static MimeBodyPart toMimeBodyPart(
        CMSTypedStream    content)
        throws SMIMEException
    {
        try
        {
            File         tmp = File.createTempFile("bcMail", ".mime");        
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
            
            return new FileMimeBodyPart(tmp);
        }
        catch (IOException e)
        {
            throw new SMIMEException("can't create temporary file: " + e, e);
        }
        catch (MessagingException e)
        {
            throw new SMIMEException("can't create part: " + e, e);
        }
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
    
    private static class FileMimeBodyPart 
        extends MimeBodyPart
     {
         private final File _file;
         
         public FileMimeBodyPart(
             File file) 
             throws MessagingException, IOException
         {
             super(new SharedFileInputStream(file.getCanonicalPath()));
             
             _file = file; 
         }
         
         public void writeTo(
             OutputStream out) 
             throws IOException, MessagingException
         {
             super.writeTo(out);
             
             contentStream.close();
             
             _file.delete();
         }
     }
}
