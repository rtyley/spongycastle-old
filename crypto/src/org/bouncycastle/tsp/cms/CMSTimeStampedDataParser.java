package org.bouncycastle.tsp.cms;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERTags;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfoParser;
import org.bouncycastle.asn1.cms.TimeStampedDataParser;
import org.bouncycastle.cms.CMSContentInfoParser;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.io.Streams;

public class CMSTimeStampedDataParser
    extends CMSContentInfoParser
{
    private TimeStampedDataParser timeStampedData;
    private TimeStampDataUtil util;

    public CMSTimeStampedDataParser(InputStream in)
        throws CMSException
    {
        super(in);

        initialize(_contentInfo);
    }

    public CMSTimeStampedDataParser(byte[] baseData)
        throws CMSException
    {
        this(new ByteArrayInputStream(baseData));
    }

    private void initialize(ContentInfoParser contentInfo)
        throws CMSException
    {
        try
        {
            if (CMSObjectIdentifiers.timestampedData.equals(contentInfo.getContentType()))
            {
                this.timeStampedData = TimeStampedDataParser.getInstance(contentInfo.getContent(DERTags.SEQUENCE));
            }
            else
            {
                throw new IllegalArgumentException("Malformed content - type must be " + CMSObjectIdentifiers.timestampedData.getId());
            }
        }
        catch (IOException e)
        {
            throw new CMSException("parsing exception: " + e.getMessage(), e);
        }
    }

    public byte[] calculateNextHash(DigestCalculator calculator)
        throws CMSException
    {
        return util.calculateNextHash(calculator);
    }

    public InputStream getContent()
    {
        if (timeStampedData.getContent() != null)
        {
            return timeStampedData.getContent().getOctetStream();
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

    public DigestCalculator getMessageImprintDigestCalculator(DigestCalculatorProvider calculatorProvider)
        throws OperatorCreationException
    {
        try
        {
            parseTimeStamps();
        }
        catch (CMSException e)
        {
            throw new OperatorCreationException("unable to extract algorithm ID: " + e.getMessage(), e);
        }

        return util.getMessageImprintDigestCalculator(calculatorProvider);
    }

    public TimeStampToken[] getTimeStampTokens()
        throws CMSException
    {
        parseTimeStamps();

        return util.getTimeStampTokens();
    }

    /**
     * Validate the digests present in the TimeStampTokens contained in the CMSTimeStampedData.
     */
    public void validate(DigestCalculatorProvider calculatorProvider, byte[] dataDigest)
        throws ImprintDigestInvalidException, CMSException
    {
        parseTimeStamps();

        util.validate(calculatorProvider, dataDigest);
    }

    public void validate(DigestCalculatorProvider calculatorProvider, byte[] dataDigest, TimeStampToken timeStampToken)
        throws ImprintDigestInvalidException, CMSException
    {
        parseTimeStamps();

        util.validate(calculatorProvider, dataDigest, timeStampToken);
    }

    private void parseTimeStamps()
        throws CMSException
    {
        try
        {
            if (util == null)
            {
                InputStream cont = this.getContent();

                if (cont != null)
                {
                    Streams.drain(cont);
                }

                util = new TimeStampDataUtil(timeStampedData);
            }
        }
        catch (IOException e)
        {
            throw new CMSException("unable to parse evidence block: " + e.getMessage(), e);
        }
    }
}
