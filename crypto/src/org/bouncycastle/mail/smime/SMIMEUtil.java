package org.bouncycastle.mail.smime;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.mail.smime.util.CRLFOutputStream;
import org.bouncycastle.mail.smime.util.FileBackedMimeBodyPart;

import javax.mail.BodyPart;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.internet.ContentType;
import javax.mail.internet.MimeBodyPart;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class SMIMEUtil
{
    private static final int BUF_SIZE = 32760;
    
    static boolean isCanonicalisationRequired(
        MimeBodyPart   bodyPart,
        String defaultContentTransferEncoding) 
        throws MessagingException
    {
        String[]        cte = bodyPart.getHeader("Content-Transfer-Encoding");
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
    
    static class LineOutputStream extends FilterOutputStream
    {
        private static byte newline[];

        public LineOutputStream(OutputStream outputstream)
        {
            super(outputstream);
        }

        public void writeln(String s)
            throws MessagingException
        {
            try
            {
                byte abyte0[] = getBytes(s);
                super.out.write(abyte0);
                super.out.write(newline);
            }
            catch(Exception exception)
            {
                throw new MessagingException("IOException", exception);
            }
        }

        public void writeln()
            throws MessagingException
        {
            try
            {
                super.out.write(newline);
            }
            catch(Exception exception)
            {
                throw new MessagingException("IOException", exception);
            }
        }

        static 
        {
            newline = new byte[2];
            newline[0] = 13;
            newline[1] = 10;
        }
        
        private static byte[] getBytes(String s)
        {
            char ac[] = s.toCharArray();
            int i = ac.length;
            byte abyte0[] = new byte[i];
            int j = 0;

            while (j < i)
            {
                abyte0[j] = (byte)ac[j++];
            }

            return abyte0;
        }
    }

    static void outputBodyPart(
        OutputStream out,
        BodyPart     bodyPart,
        String       defaultContentTransferEncoding) 
        throws MessagingException, IOException
    {
        if (bodyPart instanceof MimeBodyPart)
        {
            MimeBodyPart    mimePart = (MimeBodyPart)bodyPart;
            String[]        cte = mimePart.getHeader("Content-Transfer-Encoding");
            String          contentTransferEncoding;

            if (mimePart.getContent() instanceof Multipart)
            {
                Multipart mp = (Multipart)bodyPart.getContent();
                ContentType contentType = new ContentType(mp.getContentType());
                String boundary = "--" + contentType.getParameter("boundary");

                SMIMEUtil.LineOutputStream lOut = new SMIMEUtil.LineOutputStream(out);

                Enumeration headers = mimePart.getAllHeaderLines();
                while (headers.hasMoreElements())
                {
                    lOut.writeln((String)headers.nextElement());
                }

                lOut.writeln();      // CRLF separator

                for (int i = 0; i < mp.getCount(); i++)
                {
                    lOut.writeln(boundary);
                    outputBodyPart(out, mp.getBodyPart(i), defaultContentTransferEncoding);
                    lOut.writeln();       // CRLF terminator
                }

                lOut.writeln(boundary + "--");
                return;
            }

            if (cte == null)
            {
                contentTransferEncoding = defaultContentTransferEncoding;
            }
            else
            {
                contentTransferEncoding = cte[0];
            }

            if (!contentTransferEncoding.equalsIgnoreCase("base64")
                   && !contentTransferEncoding.equalsIgnoreCase("quoted-printable"))
            {
                if (!contentTransferEncoding.equalsIgnoreCase("binary"))
                {
                    out = new CRLFOutputStream(out);
                }
                bodyPart.writeTo(out);
                out.flush();
                return;
            }
        
            // 
            // Special handling for Base64 or quoted-printable encoded
            // body part - this is to get around JavaMail's habit of
            // decoding and then re-encoding base64 data...
            //

            //
            // Write headers
            //
            LineOutputStream outLine = new LineOutputStream(out);
            for (Enumeration e = mimePart.getAllHeaderLines(); e.hasMoreElements();) 
            {
                outLine.writeln((String)e.nextElement());
            }

            outLine.writeln();
            outLine.flush();

            //
            // Write raw content, performing canonicalization
            //
            InputStream in = mimePart.getRawInputStream();
            CRLFOutputStream outCRLF = new CRLFOutputStream(out);

            byte[]      buf = new byte[BUF_SIZE];

            int len;
            while ((len = in.read(buf, 0, buf.length)) > 0)
            {
                outCRLF.write(buf, 0, len);
            }

            outCRLF.flush();
        }
        else
        {
            if (!defaultContentTransferEncoding.equalsIgnoreCase("binary"))
            {
                out = new CRLFOutputStream(out);
            }

            bodyPart.writeTo(new CRLFOutputStream(out));
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
            return new FileBackedMimeBodyPart(content.getContentStream(), file);
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
