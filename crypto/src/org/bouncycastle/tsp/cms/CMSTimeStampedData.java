package org.bouncycastle.tsp.cms;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.Evidence;
import org.bouncycastle.asn1.cms.TimeStampAndCRL;
import org.bouncycastle.asn1.cms.TimeStampTokenEvidence;
import org.bouncycastle.asn1.cms.TimeStampedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.tsp.TimeStampToken;

public class CMSTimeStampedData
{
    private TimeStampedData timeStampedData;

    public CMSTimeStampedData(ContentInfo contentInfo)
    {
        this.timeStampedData = TimeStampedData.getInstance(contentInfo);
    }

    public byte[] calculateNextHash(DigestCalculator calculator)
        throws CMSException
    {
        Evidence evidence = timeStampedData.getTemporalEvidence();
        TimeStampAndCRL[] timeStamps = evidence.getTstEvidence().toTimeStampAndCRLArray();

        TimeStampAndCRL tspToken = timeStamps[timeStamps.length - 1];

        OutputStream out = calculator.getOutputStream();

        try
        {
            out.write(tspToken.getDEREncoded());

            out.close();

            return calculator.getDigest();
        }
        catch (IOException e)
        {
            throw new CMSException("exception calculating hash: " + e.getMessage(), e);
        }
    }

    /**
     * Return a new timeStampedData object with the additional token attached.
     */
    public CMSTimeStampedData addTimeStamp(TimeStampToken token)
    {
        Evidence evidence = timeStampedData.getTemporalEvidence();
        TimeStampAndCRL[] timeStamps = evidence.getTstEvidence().toTimeStampAndCRLArray();
        TimeStampAndCRL[] newTimeStamps = new TimeStampAndCRL[timeStamps.length + 1];

        System.arraycopy(timeStamps, 0, newTimeStamps, 0, timeStamps.length);

        newTimeStamps[timeStamps.length] = new TimeStampAndCRL(token.toCMSSignedData().getContentInfo());

        return new CMSTimeStampedData(new ContentInfo(CMSObjectIdentifiers.timestampedData, new TimeStampedData(timeStampedData.getDataUri(), timeStampedData.getMetaData(), timeStampedData.getContent(), new Evidence(new TimeStampTokenEvidence(timeStamps)))));
    }
}
