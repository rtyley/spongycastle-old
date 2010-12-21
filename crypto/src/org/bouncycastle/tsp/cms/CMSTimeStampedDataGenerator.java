package org.bouncycastle.tsp.cms;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.BERConstructedOctetString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.Evidence;
import org.bouncycastle.asn1.cms.TimeStampAndCRL;
import org.bouncycastle.asn1.cms.TimeStampTokenEvidence;
import org.bouncycastle.asn1.cms.TimeStampedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.io.TeeOutputStream;

public class CMSTimeStampedDataGenerator
    extends CMSTimeStampedGenerator
{
    private ByteArrayOutputStream contentOut = new ByteArrayOutputStream();

    public byte[] calculateHash(DigestCalculator hashCalculator, CMSProcessable content)
        throws CMSException
    {
        OutputStream out = hashCalculator.getOutputStream();

        try
        {
            if (metaData != null && metaData.isHashProtected())
            {
                out.write(metaData.getDEREncoded());
            }

            if (encapsulate)
            {
                out = new TeeOutputStream(contentOut, out);
            }

            content.write(out);

            return hashCalculator.getDigest();
        }
        catch (IOException e)
        {
            throw new CMSException("exception encoding content or metadata: " + e.getMessage(), e);
        }
    }

    public CMSTimeStampedData generate(TimeStampToken timeStamp)
    {
        ASN1OctetString content = null;

        if (contentOut.size() != 0)
        {
            content = new BERConstructedOctetString(contentOut.toByteArray());
        }

        TimeStampAndCRL stamp = new TimeStampAndCRL(timeStamp.toCMSSignedData().getContentInfo());

        return new CMSTimeStampedData(new ContentInfo(CMSObjectIdentifiers.timestampedData, new TimeStampedData(new DERIA5String(dataUri.toString()), metaData, content, new Evidence(new TimeStampTokenEvidence(stamp)))));
    }
}
