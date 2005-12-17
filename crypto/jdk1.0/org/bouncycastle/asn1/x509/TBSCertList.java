
package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTCTime;

/**
 * PKIX RFC-2459
 *
 * <pre>
 * TBSCertList  ::=  SEQUENCE  {
 *      version                 Version OPTIONAL,
 *                                   -- if present, shall be v2
 *      signature               AlgorithmIdentifier,
 *      issuer                  Name,
 *      thisUpdate              Time,
 *      nextUpdate              Time OPTIONAL,
 *      revokedCertificates     SEQUENCE OF SEQUENCE  {
 *           userCertificate         CertificateSerialNumber,
 *           revocationDate          Time,
 *           crlEntryExtensions      Extensions OPTIONAL
 *                                         -- if present, shall be v2
 *                                }  OPTIONAL,
 *      crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
 *                                         -- if present, shall be v2
 *                                }
 * </pre>
 */

public class TBSCertList
    implements DEREncodable
{
    ASN1Sequence  seq;

    DERInteger              version;
    AlgorithmIdentifier     signature;
    X509Name                issuer;
    DERUTCTime                thisUpdate;
    DERUTCTime                nextUpdate;
    CRLEntry[]                revokedCertificates;
    X509Extensions          crlExtensions;

    public TBSCertList(
        ASN1Sequence  seq)
    {
        int seqPos = 0;

        this.seq = seq;

        if (seq.getObjectAt(seqPos) instanceof DERInteger)
        {
            version = (DERInteger)seq.getObjectAt(seqPos++);
        }
        else
        {
            version = new DERInteger(0);
        }

        if (seq.getObjectAt(seqPos) instanceof AlgorithmIdentifier)
        {
            signature = (AlgorithmIdentifier)seq.getObjectAt(seqPos++);
        }
        else
        {
            signature = new AlgorithmIdentifier((ASN1Sequence)seq.getObjectAt(seqPos++));
        }

        if (seq.getObjectAt(seqPos) instanceof X509Name)
        {
            issuer = (X509Name)seq.getObjectAt(seqPos++);
        }
        else
        {
            issuer = new X509Name((ASN1Sequence)seq.getObjectAt(seqPos++));
        }

        thisUpdate = (DERUTCTime)seq.getObjectAt(seqPos++);

        if (seqPos < seq.size()
            && seq.getObjectAt(seqPos) instanceof DERUTCTime)
        {
            nextUpdate = (DERUTCTime)seq.getObjectAt(seqPos++);
        }

        if (seqPos < seq.size()
            && !(seq.getObjectAt(seqPos) instanceof DERTaggedObject))
        {
            ASN1Sequence certs = (ASN1Sequence)seq.getObjectAt(seqPos++);
            revokedCertificates = new CRLEntry[certs.size()];

            for (int i = 0; i < revokedCertificates.length; i++)
            {
                revokedCertificates[i] = new CRLEntry((ASN1Sequence)certs.getObjectAt(i));
            }
        }

        if (seqPos < seq.size()
            && seq.getObjectAt(seqPos) instanceof DERTaggedObject)
        {
            crlExtensions = new X509Extensions((ASN1Sequence)((DERTaggedObject)seq.getObjectAt(seqPos++)).getObject());
        }
    }

    public int getVersion()
    {
        return version.getValue().intValue() + 1;
    }

    public DERInteger getVersionNumber()
    {
        return version;
    }

    public AlgorithmIdentifier getSignature()
    {
        return signature;
    }

    public X509Name getIssuer()
    {
        return issuer;
    }

    public DERUTCTime getThisUpdate()
    {
        return thisUpdate;
    }

    public DERUTCTime getNextUpdate()
    {
        return nextUpdate;
    }

    public CRLEntry[] getRevokedCertificates()
    {
        return revokedCertificates;
    }

    public X509Extensions getExtensions()
    {
        return crlExtensions;
    }

    public DERObject getDERObject()
    {
        return seq;
    }
}

