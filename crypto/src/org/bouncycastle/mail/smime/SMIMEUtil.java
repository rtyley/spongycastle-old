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
import javax.mail.internet.MimeBodyPart;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.mail.smime.util.SharedFileInputStream;

public class SMIMEUtil
{
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
     * return the MimeBodyPart described in {@link CMSTypedStream} content
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
            
            return new MimeBodyPart(new SharedFileInputStream(tmp.getCanonicalPath()));
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
}
