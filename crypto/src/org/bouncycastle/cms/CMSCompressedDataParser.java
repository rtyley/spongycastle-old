package org.bouncycastle.cms;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.InflaterInputStream;

import org.bouncycastle.asn1.cms.CompressedDataParser;
import org.bouncycastle.asn1.cms.ContentInfoParser;
import org.bouncycastle.asn1.ASN1OctetStringParser;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.DERTags;

/**
 * Class for reading a CMS Compressed Data stream.
 * <pre>
 *     CMSCompressedDataParser cp = new CMSCompressedDataParser(inputStream);
 *      
 *     process(cp.getContent().getContentStream());
 * </pre>
 *  Note: this class does not introduce buffering - if you are processing large files you should create
 *  the parser with:
 *  <pre>
 *      CMSCompressedDataParser     ep = new CMSCompressedDataParser(new BufferedInputStream(inputStream, bufSize));
 *  </pre>
 *  where bufSize is a suitably large buffer size.
 */
public class CMSCompressedDataParser
    extends CMSContentInfoParser
{
    public CMSCompressedDataParser(
        byte[]    compressedData) 
        throws CMSException
    {
        this(new ByteArrayInputStream(compressedData));
    }

    public CMSCompressedDataParser(
        InputStream    compressedData) 
        throws CMSException
    {
        super(compressedData);
    }

    public CMSTypedStream  getContent()
        throws CMSException
    {
        try
        {
            CompressedDataParser  comData = new CompressedDataParser((ASN1SequenceParser)_contentInfo.getContent(DERTags.SEQUENCE));
            ContentInfoParser     content = comData.getEncapContentInfo();
    
            ASN1OctetStringParser bytes = (ASN1OctetStringParser)content.getContent(DERTags.OCTET_STRING);
    
            return new CMSTypedStream(content.getContentType().toString(), new InflaterInputStream(bytes.getOctetStream()));
        }
        catch (IOException e)
        {
            throw new CMSException("IOException reading compressed content.", e);
        }
    }
}
