package org.bouncycastle.mail.smime;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateParsingException;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.jce.PrincipalUtil;

public class SMIMEUtil
{
    /**
     * return the MimeBodyPart described in the raw bytes provided in content
     */
    public static MimeBodyPart toMimeBodyPart(
        byte[]    content)
        throws SMIMEException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(content);

        try
        {
            MimeBodyPart part = new MimeBodyPart(bIn);

            return part;
        }
        catch (MessagingException e)
        {
            throw new SMIMEException("exception creating body part.", e);
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
