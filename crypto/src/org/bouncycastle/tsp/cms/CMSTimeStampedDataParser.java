package org.bouncycastle.tsp.cms;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERTags;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.ContentInfoParser;
import org.bouncycastle.asn1.cms.Evidence;
import org.bouncycastle.asn1.cms.MetaData;
import org.bouncycastle.asn1.cms.TimeStampAndCRL;
import org.bouncycastle.asn1.cms.TimeStampedDataParser;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSContentInfoParser;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

public class CMSTimeStampedDataParser
    extends CMSContentInfoParser
{
    private TimeStampedDataParser timeStampedData;
    private TimeStampAndCRL[] timeStamps;

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
        TimeStampToken token;

        try
        {
            parseTimeStamps();

            token = this.getTimeStampToken(timeStamps[0]);
        }
        catch (CMSException e)
        {
            throw new OperatorCreationException("unable to extract algorithm ID: " + e.getMessage(), e);
        }

        TimeStampTokenInfo info = token.getTimeStampInfo();
        String algOID = info.getMessageImprintAlgOID();

        DigestCalculator calc = calculatorProvider.get(new AlgorithmIdentifier(algOID));
        MetaData metaData = this.timeStampedData.getMetaData();
        if (metaData != null && metaData.isHashProtected())
        {
            try
            {
                calc.getOutputStream().write(metaData.getDEREncoded());
            }
            catch (IOException e)
            {
                throw new OperatorCreationException("unable to initialise calculator from metaData: " + e.getMessage(), e);
            }
        }

        return calc;
    }

    public TimeStampToken[] getTimeStampTokens()
        throws CMSException
    {
        parseTimeStamps();

        TimeStampToken[] tokens = new TimeStampToken[timeStamps.length];
        for (int i = 0; i < timeStamps.length; i++)
        {
            tokens[i] = this.getTimeStampToken(timeStamps[i]);
        }

        return tokens;
    }

    private void parseTimeStamps()
        throws CMSException
    {
        try
        {
            if (timeStamps == null)
            {
                InputStream cont = this.getContent();

                if (cont != null)
                {
                    Streams.drain(cont);
                }
                
                Evidence evidence = this.timeStampedData.getTemporalEvidence();
                timeStamps = evidence.getTstEvidence().toTimeStampAndCRLArray();
            }
        }
        catch (IOException e)
        {
            throw new CMSException("unable to parse evidence block: " + e.getMessage(), e);
        }
    }

    /**
     * Validate the digests present in the TimeStampTokens contained in the CMSTimeStampedData.
     */
    public void validate(DigestCalculatorProvider calculatorProvider, byte[] dataDigest)
        throws ImprintDigestInvalidException, CMSException
    {
        parseTimeStamps();

        byte[] currentDigest = dataDigest;

        for (int i = 0; i < timeStamps.length; i++)
        {
            try
            {
                TimeStampToken token = this.getTimeStampToken(timeStamps[i]);
                if (i > 0)
                {
                    TimeStampTokenInfo info = token.getTimeStampInfo();
                    DigestCalculator calculator = calculatorProvider.get(info.getHashAlgorithm());

                    calculator.getOutputStream().write(timeStamps[i - 1].getDEREncoded());

                    currentDigest = calculator.getDigest();
                }

                this.compareDigest(token, currentDigest);
            }
            catch (IOException e)
            {
                throw new CMSException("exception calculating hash: " + e.getMessage(), e);
            }
            catch (OperatorCreationException e)
            {
                throw new CMSException("cannot create digest: " + e.getMessage(), e);
            }
        }
    }

    public void validate(DigestCalculatorProvider calculatorProvider, byte[] dataDigest, TimeStampToken timeStampToken)
        throws ImprintDigestInvalidException, CMSException
    {
        parseTimeStamps();

        byte[] currentDigest = dataDigest;
        byte[] encToken;

        try
        {
            encToken = timeStampToken.getEncoded();
        }
        catch (IOException e)
        {
            throw new CMSException("exception encoding timeStampToken: " + e.getMessage(), e);
        }

        for (int i = 0; i < timeStamps.length; i++)
        {
            try
            {
                TimeStampToken token = this.getTimeStampToken(timeStamps[i]);
                if (i > 0)
                {
                    TimeStampTokenInfo info = token.getTimeStampInfo();
                    DigestCalculator calculator = calculatorProvider.get(info.getHashAlgorithm());

                    calculator.getOutputStream().write(timeStamps[i - 1].getDEREncoded());

                    currentDigest = calculator.getDigest();
                }

                this.compareDigest(token, currentDigest);

                if (Arrays.areEqual(token.getEncoded(), encToken))
                {
                    return;
                }
            }
            catch (IOException e)
            {
                throw new CMSException("exception calculating hash: " + e.getMessage(), e);
            }
            catch (OperatorCreationException e)
            {
                throw new CMSException("cannot create digest: " + e.getMessage(), e);
            }
        }

        throw new ImprintDigestInvalidException("passed in token not associated with timestamps present", timeStampToken);
    }

    private TimeStampToken getTimeStampToken(TimeStampAndCRL timeStampAndCRL)
        throws CMSException
    {
        ContentInfo timeStampToken = timeStampAndCRL.getTimeStampToken();

        try
        {
            TimeStampToken token = new TimeStampToken(timeStampToken);
            return token;
        }
        catch (IOException e)
        {
            throw new CMSException("unable to parse token data: " + e.getMessage(), e);
        }
        catch (TSPException e)
        {
            if (e.getCause() instanceof CMSException)
            {
                throw (CMSException)e.getCause();
            }

            throw new CMSException("token data invalid: " + e.getMessage(), e);
        }
        catch (IllegalArgumentException e)
        {
            throw new CMSException("token data invalid: " + e.getMessage(), e);
        }
    }

    private void compareDigest(TimeStampToken timeStampToken, byte[] digest)
        throws ImprintDigestInvalidException
    {
        TimeStampTokenInfo info = timeStampToken.getTimeStampInfo();
        byte[] tsrMessageDigest = info.getMessageImprintDigest();

        if (!Arrays.areEqual(digest, tsrMessageDigest))
        {
            throw new ImprintDigestInvalidException("hash calculated is different from MessageImprintDigest found in TimeStampToken", timeStampToken);
        }
    }
}
