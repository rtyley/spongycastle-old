package org.bouncycastle.tsp.cms;

import java.net.URI;

import org.bouncycastle.asn1.cms.MetaData;

public class CMSTimeStampedGenerator
{
    protected boolean encapsulate;
    protected MetaData metaData;
    protected URI dataUri;

    public void setEncapsulate(boolean encapsulate)
    {
        this.encapsulate = encapsulate;
    }
    
    public void setDataUri(URI dataUri)
    {
        this.dataUri = dataUri;
    }
}
