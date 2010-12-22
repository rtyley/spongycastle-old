package org.bouncycastle.tsp.cms;

import java.net.URL;

import org.bouncycastle.asn1.cms.MetaData;

public class CMSTimeStampedGenerator
{
    protected boolean encapsulate;
    protected MetaData metaData;
    protected URL dataUri;

    public void setEncapsulate(boolean encapsulate)
    {
        this.encapsulate = encapsulate;
    }
    
    public void setDataUri(URL dataUri)
    {
        this.dataUri = dataUri;
    }
}
