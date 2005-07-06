package org.bouncycastle.mail.smime.handlers;

import java.awt.datatransfer.DataFlavor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.activation.ActivationDataFlavor;
import javax.activation.DataContentHandler;
import javax.activation.DataSource;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMultipart;

public class multipart_signed implements DataContentHandler {
    
    /*  
     *  
     *  VARIABLES
     *  
     */ 
    
    private static final ActivationDataFlavor ADF;
    private static final DataFlavor[]         ADFs;
    
    /*  
     *  
     *  CONSTRUCTORS
     *  
     */ 
    
    static {
        ADF  = new ActivationDataFlavor(MimeMultipart.class, "multipart/signed", "Multipart Signed");
        ADFs = new DataFlavor[] { ADF };
    }
    
    /*  
     *  
     *  BUSINESS METHODS
     *  
     */ 
    
    
    public Object getContent(DataSource _ds) 
        throws IOException {
        
        try {
            return new MimeMultipart(_ds); 
        } catch (MessagingException ex) {
            return null;
        }
    }
    
    public Object getTransferData(DataFlavor _df, DataSource _ds) 
        throws IOException {
        
        if (ADF.equals(_df)) {
            return getContent(_ds);
        }
        else {
            return null;
        }
    }
    
    public DataFlavor[] getTransferDataFlavors() {
        return ADFs;
    }
    
    public void writeTo(Object _obj, String _mimeType, OutputStream _os) 
        throws IOException
    {
        
        if (_obj instanceof MimeMultipart)
        {
            try
            {
                ((MimeMultipart)_obj).writeTo(_os);
            }
            catch (MessagingException ex)
            {
                throw new IOException(ex.getMessage());
            }
        }
        else if(_obj instanceof byte[])
        {
            _os.write((byte[])_obj);
        }
        else if (_obj instanceof InputStream)
        {
            int            b;
            InputStream    in = (InputStream)_obj;

            while ((b = in.read()) >= 0)
            {
                _os.write(b);
            }
        }
        else
        {
            throw new IOException("unknown object in writeTo " + _obj);
        }
    }
}
