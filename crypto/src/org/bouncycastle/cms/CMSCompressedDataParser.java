package org.bouncycastle.cms;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.InflaterInputStream;

import org.bouncycastle.sasn1.Asn1OctetString;
import org.bouncycastle.sasn1.Asn1Sequence;
import org.bouncycastle.sasn1.BerTag;
import org.bouncycastle.sasn1.cms.CompressedDataParser;
import org.bouncycastle.sasn1.cms.ContentInfoParser;

/**
 * Class for reading a CMS Compressed Data stream.
 * <pre>
 *     CMSCompressedDataParser cp = new CMSCompressedDataParser(bOut.toByteArray());
 *      
 *     process(cp.getContent().getContentStream());
 * </pre>
 */
public class CMSCompressedDataParser
    extends CMSContentInfoParser
{
    public CMSCompressedDataParser(
        byte[]    compressedData) 
        throws CMSException
    {
        this(readContentInfo(new ByteArrayInputStream(compressedData)));
    }

    public CMSCompressedDataParser(
        InputStream    compressedData) 
        throws CMSException
    {
        this(readContentInfo(compressedData));
    }

    public CMSCompressedDataParser(
        ContentInfoParser contentInfo)
        throws CMSException
    {
        super(contentInfo);
    }

    public CMSTypedStream  getContent()
        throws CMSException
    {
        try
        {
            CompressedDataParser  comData = new CompressedDataParser((Asn1Sequence)_contentInfo.getContent(BerTag.SEQUENCE));
            ContentInfoParser     content = comData.getEncapContentInfo();
    
            Asn1OctetString bytes = (Asn1OctetString)content.getContent(BerTag.OCTET_STRING);
    
            return new CMSTypedStream(content.getContentType().toString(), new InflaterInputStream(bytes.getOctetStream()));
        }
        catch (IOException e)
        {
            throw new CMSException("IOException reading compressed content.", e);
        }
    }
}
