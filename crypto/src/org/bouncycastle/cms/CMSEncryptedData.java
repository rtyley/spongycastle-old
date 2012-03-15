package org.bouncycastle.cms;

import org.bouncycastle.asn1.cms.ContentInfo;

public class CMSEncryptedData
{
    private ContentInfo contentInfo;

    public CMSEncryptedData(ContentInfo contentInfo)
    {
        this.contentInfo = contentInfo;
    }

    /**
     * return the ContentInfo
     */
    public ContentInfo toASN1Structure()
    {
        return contentInfo;
    }
}
