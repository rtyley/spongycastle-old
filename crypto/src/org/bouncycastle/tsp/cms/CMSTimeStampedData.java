package org.bouncycastle.tsp.cms;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.Evidence;
import org.bouncycastle.asn1.cms.TimeStampAndCRL;
import org.bouncycastle.asn1.cms.TimeStampTokenEvidence;
import org.bouncycastle.asn1.cms.TimeStampedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TimeStampToken;

public class CMSTimeStampedData
{
    private TimeStampedData timeStampedData;
    private ContentInfo contentInfo;
    private TimeStampDataUtil util;

    public CMSTimeStampedData(ContentInfo contentInfo)
    {
        this.initialize(contentInfo);
    }

    public CMSTimeStampedData(InputStream in)
        throws IOException
    {
        try
        {
            initialize(ContentInfo.getInstance(new ASN1InputStream(in).readObject()));
        }
        catch (ClassCastException e)
        {
            throw new IOException("Malformed content: " + e);
        }
        catch (IllegalArgumentException e)
        {
            throw new IOException("Malformed content: " + e);
        }
    }

    public CMSTimeStampedData(byte[] baseData)
        throws IOException
    {
        this(new ByteArrayInputStream(baseData));
    }

    private void initialize(ContentInfo contentInfo)
    {
        this.contentInfo = contentInfo;

        if (CMSObjectIdentifiers.timestampedData.equals(contentInfo.getContentType()))
        {
            this.timeStampedData = TimeStampedData.getInstance(contentInfo.getContent());
        }
        else
        {
            throw new IllegalArgumentException("Malformed content - type must be " + CMSObjectIdentifiers.timestampedData.getId());
        }

        util = new TimeStampDataUtil(this.timeStampedData);
    }

    public byte[] calculateNextHash(DigestCalculator calculator)
        throws CMSException
    {
        return util.calculateNextHash(calculator);
    }

    /**
     * Return a new timeStampedData object with the additional token attached.
     *
     * @throws CMSException
     */
    public CMSTimeStampedData addTimeStamp(TimeStampToken token)
        throws CMSException
    {
        TimeStampAndCRL[] timeStamps = util.getTimeStamps();
        TimeStampAndCRL[] newTimeStamps = new TimeStampAndCRL[timeStamps.length + 1];

        System.arraycopy(timeStamps, 0, newTimeStamps, 0, timeStamps.length);

        newTimeStamps[timeStamps.length] = new TimeStampAndCRL(token.toCMSSignedData().getContentInfo());

        return new CMSTimeStampedData(new ContentInfo(CMSObjectIdentifiers.timestampedData, new TimeStampedData(timeStampedData.getDataUri(), timeStampedData.getMetaData(), timeStampedData.getContent(), new Evidence(new TimeStampTokenEvidence(timeStamps)))));
    }

    public byte[] getContent()
    {
        if (timeStampedData.getContent() != null)
        {
            return timeStampedData.getContent().getOctets();
        }

        return null;
    }

    public URI getDataUri()
        throws URISyntaxException
    {
        DERIA5String dataURI = this.timeStampedData.getDataUri();

        if (dataURI != null)
        {
            return new URI(dataURI.getString());
        }

        return null;
    }

    public TimeStampToken[] getTimeStampTokens()
        throws CMSException
    {
        return util.getTimeStampTokens();
    }

    public DigestCalculator getMessageImprintDigestCalculator(DigestCalculatorProvider calculatorProvider)
        throws OperatorCreationException
    {
        return util.getMessageImprintDigestCalculator(calculatorProvider);
    }

    /**
     * Validate the digests present in the TimeStampTokens contained in the CMSTimeStampedData.
     */
    public void validate(DigestCalculatorProvider calculatorProvider, byte[] dataDigest)
        throws ImprintDigestInvalidException, CMSException
    {
        util.validate(calculatorProvider, dataDigest);
    }

    public void validate(DigestCalculatorProvider calculatorProvider, byte[] dataDigest, TimeStampToken timeStampToken)
        throws ImprintDigestInvalidException, CMSException
    {
        util.validate(calculatorProvider, dataDigest, timeStampToken);
    }

    public byte[] getEncoded()
        throws IOException
    {
        return contentInfo.getEncoded();
    }
}
