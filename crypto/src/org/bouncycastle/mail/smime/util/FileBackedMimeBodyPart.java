package org.bouncycastle.mail.smime.util;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;

public class FileBackedMimeBodyPart 
    extends MimeBodyPart
 {
     private final File _file;

     public FileBackedMimeBodyPart(
         File file)
         throws MessagingException, IOException
     {
         super(new SharedFileInputStream(file));
         
         _file = file;
     }
     
     public void writeTo(
         OutputStream out) 
         throws IOException, MessagingException
     {
         if (!_file.exists())
         {
             throw new IOException("file " + _file.getCanonicalPath() + " no longer exists.");
         }
         
         super.writeTo(out);
     }

    public void dispose() 
        throws IOException
    {
        ((SharedFileInputStream)contentStream).dispose();
        
        if (!_file.delete())
        {
            throw new IOException("deletion of underlying file <" + _file.getCanonicalPath() + "> failed.");
        }
    }
 }
