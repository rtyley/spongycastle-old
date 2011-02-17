package org.bouncycastle.tsp.cms;

import java.io.IOException;

import org.bouncycastle.asn1.cms.MetaData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.DigestCalculator;

class MetaDataUtil
{
    private final MetaData          metaData;

    MetaDataUtil(MetaData metaData)
    {
        this.metaData = metaData;
    }

    void initialiseMessageImprintDigestCalculator(DigestCalculator calculator)
        throws CMSException
    {
        if (metaData != null && metaData.isHashProtected())
        {
            try
            {
                calculator.getOutputStream().write(metaData.getDEREncoded());
            }
            catch (IOException e)
            {
                throw new CMSException("unable to initialise calculator from metaData: " + e.getMessage(), e);
            }
        }
    }
}
