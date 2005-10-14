package org.bouncycastle.mail.smime.handlers;

import java.awt.datatransfer.DataFlavor;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.activation.ActivationDataFlavor;
import javax.activation.DataContentHandler;
import javax.activation.DataSource;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.mail.smime.SMIMEStreamingProcessor;

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
                ((MimeMultipart)obj).writeTo(os);
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
}
