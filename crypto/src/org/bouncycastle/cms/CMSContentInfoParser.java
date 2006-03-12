package org.bouncycastle.cms;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.sasn1.Asn1InputStream;
import org.bouncycastle.sasn1.Asn1Sequence;
import org.bouncycastle.sasn1.cms.ContentInfoParser;

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
            Asn1InputStream in = new Asn1InputStream(data);
    
            _contentInfo = new ContentInfoParser((Asn1Sequence)in.readObject());
        }
        catch (IOException e)
        {
            throw new CMSException("IOException reading content.", e);
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
