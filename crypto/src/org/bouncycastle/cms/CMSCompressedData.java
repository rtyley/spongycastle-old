package org.bouncycastle.cms;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.InflaterInputStream;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.cms.CompressedData;
import org.bouncycastle.asn1.cms.ContentInfo;

/**
 * containing class for an CMS Compressed Data object
 */
public class CMSCompressedData
{
    ContentInfo                 contentInfo;

    public CMSCompressedData(
        byte[]    compressedData) 
        throws CMSException
    {
        this(CMSUtils.readContentInfo(compressedData));
    }

    public CMSCompressedData(
        InputStream    compressedData) 
        throws CMSException
    {
        this(CMSUtils.readContentInfo(compressedData));
    }

    public CMSCompressedData(
        ContentInfo contentInfo)
        throws CMSException
    {
        this.contentInfo = contentInfo;
    }

    public byte[] getContent()
        throws CMSException
    {
        CompressedData  comData = CompressedData.getInstance(contentInfo.getContent());
        ContentInfo     content = comData.getEncapContentInfo();

        ASN1OctetString bytes = (ASN1OctetString)content.getContent();

        InflaterInputStream     zIn = new InflaterInputStream(new ByteArrayInputStream(bytes.getOctets()));
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();

        byte[]  buf = new byte[1024];
        int     len;

        try
        {
            while ((len = zIn.read(buf, 0, buf.length)) > 0)
            {
                bOut.write(buf, 0, len);
            }
        }
        catch (IOException e)
        {
            throw new CMSException("exception reading compressed stream.", e);
        }

        return bOut.toByteArray();
    }

    /**
     * return the ASN.1 encoded representation of this object.
     */
    public byte[] getEncoded()
        throws IOException
    {
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        ASN1OutputStream        aOut = new ASN1OutputStream(bOut);

        aOut.writeObject(contentInfo);

        return bOut.toByteArray();
    }
}
