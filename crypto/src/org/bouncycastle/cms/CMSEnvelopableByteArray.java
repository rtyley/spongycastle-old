package org.bouncycastle.cms;


/**
 * a holding class for a byte array of data to be enveloped.
 * @deprecated use CMSProcessable
 */
public class CMSEnvelopableByteArray
    extends CMSProcessableByteArray
{
    public CMSEnvelopableByteArray(
        byte[]  bytes)
    {
        super(bytes);
    }
}
