package org.bouncycastle.mail.smime.handlers;

import org.bouncycastle.mail.smime.SMIMEStreamingProcessor;

import javax.activation.ActivationDataFlavor;
import javax.activation.DataContentHandler;
import javax.activation.DataSource;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.internet.ContentType;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;
import java.awt.datatransfer.DataFlavor;
import java.io.BufferedInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Enumeration;

public class multipart_signed 
    implements DataContentHandler 
{
    private static final ActivationDataFlavor ADF = new ActivationDataFlavor(MimeMultipart.class, "multipart/signed", "Multipart Signed");
    private static final DataFlavor[]         DFS = new DataFlavor[] { ADF };
    
    public Object getContent(DataSource ds) 
        throws IOException 
    {
        try
        {
            return new MimeMultipart(ds);
        }
        catch (MessagingException ex)
        {
            return null;
        }
    }
    
    public Object getTransferData(DataFlavor df, DataSource ds) 
        throws IOException 
    {    
        if (ADF.equals(df))
        {
            return getContent(ds);
        }
        else
        {
            return null;
        }
    }
    
    public DataFlavor[] getTransferDataFlavors() 
    {
        return DFS;
    }
    
    public void writeTo(Object obj, String _mimeType, OutputStream os) 
        throws IOException
    {
        
        if (obj instanceof MimeMultipart)
        {
            try
            {
                outputBodyPart(os, obj);
            }
            catch (MessagingException ex)
            {
                throw new IOException(ex.getMessage());
            }
        }
        else if(obj instanceof byte[])
        {
            os.write((byte[])obj);
        }
        else if (obj instanceof InputStream)
        {
            int         b;
            InputStream in = (InputStream)obj;
            
            if (!(in instanceof BufferedInputStream))
            {
                in = new BufferedInputStream(in);
            }

            while ((b = in.read()) >= 0)
            {
                os.write(b);
            }
        }
        else if (obj instanceof SMIMEStreamingProcessor)
        {
            SMIMEStreamingProcessor processor = (SMIMEStreamingProcessor)obj;

            processor.write(os);
        }
        else
        {
            throw new IOException("unknown object in writeTo " + obj);
        }
    }

    /*
     * Output the mulitpart as a collection of leaves to make sure preamble text is not included.
     */
    private void outputBodyPart(
        OutputStream out,
        Object bodyPart)
        throws MessagingException, IOException
    {
        if (bodyPart instanceof Multipart)
        {
            Multipart mp = (Multipart)bodyPart;
            ContentType contentType = new ContentType(mp.getContentType());
            String boundary = "--" + contentType.getParameter("boundary");

            LineOutputStream lOut = new LineOutputStream(out);

            for (int i = 0; i < mp.getCount(); i++)
            {
                lOut.writeln(boundary);
                outputBodyPart(out, mp.getBodyPart(i));
                lOut.writeln();       // CRLF terminator
            }

            lOut.writeln(boundary + "--");
            return;
        }

        MimeBodyPart    mimePart = (MimeBodyPart)bodyPart;

        if (mimePart.getContent() instanceof Multipart)
        {
            Multipart mp = (Multipart)mimePart.getContent();

            LineOutputStream lOut = new LineOutputStream(out);

            Enumeration headers = mimePart.getAllHeaderLines();
            while (headers.hasMoreElements())
            {
                lOut.writeln((String)headers.nextElement());
            }

            lOut.writeln();      // CRLF separator

            outputBodyPart(out, mp);
            return;
        }

        mimePart.writeTo(out);
    }

    private static class LineOutputStream extends FilterOutputStream
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
}
