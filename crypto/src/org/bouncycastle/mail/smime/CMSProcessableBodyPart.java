package org.bouncycastle.mail.smime;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.mail.BodyPart;
import javax.mail.MessagingException;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;

/**
 * a holding class for a BodyPart to be processed.
 */
public class CMSProcessableBodyPart
    implements CMSProcessable
{
    private BodyPart   bodyPart;

    public CMSProcessableBodyPart(
        BodyPart    bodyPart)
    {
        this.bodyPart = bodyPart;
    }

    public InputStream read() throws IOException, CMSException
    {
        // Note: This 'obvious' implementation appears to not be the same data
//        bodyPart.getInputStream();

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        write(buf);
        return new ByteArrayInputStream(buf.toByteArray());
    }

    public void write(
        OutputStream out)
        throws IOException, CMSException
    {
        try
        {
            bodyPart.writeTo(out);
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
