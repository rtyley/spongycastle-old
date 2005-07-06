package org.bouncycastle.mail.smime;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FilterOutputStream;

import java.util.Enumeration;

import javax.mail.BodyPart;
import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;

/**
 * a holding class for a BodyPart to be processed which does CRLF canonicalisation if
 * dealing with non-binary data.
 */
public class CMSProcessableBodyPartInbound
    implements CMSProcessable
{
    private BodyPart    bodyPart;
    private byte[]      buf = new byte[4];
    private String      defaultContentTransferEncoding = "7bit";

    static class CRLFOutputStream extends FilterOutputStream
    {
        protected int lastb;
        protected static byte newline[];

        public CRLFOutputStream(OutputStream outputstream)
        {
            super(outputstream);
            lastb = -1;
        }

        public void write(int i)
            throws IOException
        {
            if(i == 13)
            {
                super.out.write(newline);
            } 
            else if(i == 10)
            {
                if(lastb != 13)
                {
                    super.out.write(newline);
                }
            } 
            else
            {
                super.out.write(i);
            }
            lastb = i;
        }

        public void write(byte abyte0[])
            throws IOException
        {
            write(abyte0, 0, abyte0.length);
        }

        public void write(byte abyte0[], int i, int j)
            throws IOException
        {
            int k = i;
            j += i;
            for(int l = k; l < j; l++)
            {
                if(abyte0[l] == 13)
                {
                    super.out.write(abyte0, k, l - k);
                    super.out.write(newline);
                    k = l + 1;
                } 
                else if(abyte0[l] == 10)
                {
                    if(lastb != 13)
                    {
                        super.out.write(abyte0, k, l - k);
                        super.out.write(newline);
                    }
                    k = l + 1;
                }
                lastb = abyte0[l];
            }

            if(j - k > 0)
            {
                super.out.write(abyte0, k, j - k);
            }
        }

        public void writeln()
            throws IOException
        {
            super.out.write(newline);
        }

        static 
        {
            newline = new byte[2];
            newline[0] = 13;
            newline[1] = 10;
        }
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
                return;
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
                return;
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
            for(int j = 0; j < i;)
            {
                abyte0[j] = (byte)ac[j++];
            }

            return abyte0;
        }
    }

    /**
     * Create a processable with the default transfer encoding of 7bit 
     * 
     * @param bodyPart body part to be processed
     */
    public CMSProcessableBodyPartInbound(
        BodyPart    bodyPart)
    {
        this.bodyPart = bodyPart;
    }

    /**
     * Create a processable with the a default transfer encoding of
     * the passed in value. 
     * 
     * @param bodyPart body part to be processed
     * @param defaultContentTransferEncoding the new default to use.
     */
    public CMSProcessableBodyPartInbound(
        BodyPart    bodyPart,
        String      defaultContentTransferEncoding)
    {
        this.bodyPart = bodyPart;
        this.defaultContentTransferEncoding = defaultContentTransferEncoding;
    }
    
    public void write(
        OutputStream out)
        throws IOException, CMSException
    {
        try
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


                int len = 0;
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
        catch (MessagingException e)
        {
            throw new CMSException("can't write BodyPart to stream.", e);
        }
    }

    public Object getContent()
    {
        return bodyPart;
    }
}
