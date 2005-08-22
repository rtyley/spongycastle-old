package org.bouncycastle.cms;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.sasn1.Asn1InputStream;
import org.bouncycastle.sasn1.Asn1Sequence;
import org.bouncycastle.sasn1.cms.ContentInfoParser;

public class CMSContentInfoParser
{
    protected ContentInfoParser _contentInfo;
    
    protected static ContentInfoParser readContentInfo(
        InputStream data)
        throws CMSException
    {
        try
        {
            Asn1InputStream in = new Asn1InputStream(data);

            return new ContentInfoParser((Asn1Sequence)in.readObject());
        }
        catch (IOException e)
        {
            throw new CMSException("IOException reading content.", e);
        }
    }
    
    protected CMSContentInfoParser(
        ContentInfoParser contentInfo)
    {
        this._contentInfo = contentInfo;
    }
}
