package org.bouncycastle.cms;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.DeflaterOutputStream;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.BERConstructedOctetString;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.CompressedData;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * General class for generating a compressed CMS message.
 * <p>
 * A simple example of usage.
 * <p>
 * <pre>
 *      CMSCompressedDataGenerator  fact = new CMSCompressedDataGenerator();
 *
 *      CMSCompressedData           data = fact.generate(content, algorithm);
 * </pre>
 */
public class CMSCompressedDataGenerator
{
    public static final String  ZLIB    = "1.2.840.113549.1.9.16.3.8";

    /**
     * base constructor
     */
    public CMSCompressedDataGenerator()
    {
    }

    private DERObject makeObj(
        byte[]  encoding)
        throws IOException
    {
        if (encoding == null)
        {
            return null;
        }

        ByteArrayInputStream    bIn = new ByteArrayInputStream(encoding);
        ASN1InputStream         aIn = new ASN1InputStream(bIn);

        return aIn.readObject();
    }

    private AlgorithmIdentifier makeAlgId(
        String  oid,
        byte[]  params)
        throws IOException
    {
        if (params != null)
        {
            return new AlgorithmIdentifier(
                            new DERObjectIdentifier(oid), makeObj(params));
        }
        else
        {
            return new AlgorithmIdentifier(new DERObjectIdentifier(oid));
        }
    }

    /**
     * generate an object that contains an CMS Compressed Data
     */
    public CMSCompressedData generate(
        CMSProcessable  content,
        String          compressionOID)
        throws CMSException
    {
        AlgorithmIdentifier     comAlgId;
        ASN1OctetString         comOcts;

        try
        {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            DeflaterOutputStream  zOut = new DeflaterOutputStream(bOut);

            content.write(zOut);

            zOut.close();

            comAlgId = makeAlgId(compressionOID, null);
            comOcts = new BERConstructedOctetString(bOut.toByteArray());
        }
        catch (IOException e)
        {
            throw new CMSException("exception encoding data.", e);
        }

        ContentInfo     comContent = new ContentInfo(
                                    CMSObjectIdentifiers.data, comOcts);

        ContentInfo     contentInfo = new ContentInfo(
                                    CMSObjectIdentifiers.compressedData,
                                    new CompressedData(comAlgId, comContent));

        return new CMSCompressedData(contentInfo);
    }
}
