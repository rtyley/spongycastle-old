package org.bouncycastle.cms;

import org.bouncycastle.asn1.cms.ContentInfoParser;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.ASN1SequenceParser;

import java.io.IOException;
import java.io.InputStream;

public class CMSContentInfoParser
{
    protected ContentInfoParser _contentInfo;
    protected InputStream       _data;

    protected CMSContentInfoParser(
        InputStream data)
        throws CMSException
    {
        _data = data;
        
        try
        {
            ASN1StreamParser in = new ASN1StreamParser(data, CMSUtils.getMaximumMemory());
    
            _contentInfo = new ContentInfoParser((ASN1SequenceParser)in.readObject());
        }
        catch (IOException e)
        {
            throw new CMSException("IOException reading content.", e);
        }
        catch (ClassCastException e)
        {
            throw new CMSException("Unexpected object reading content.", e);
        }
    }
    
    /**
     * Close the underlying data stream.
     * @throws IOException if the close fails.
     */
    public void close() throws IOException
    {
        _data.close();
    }
}
