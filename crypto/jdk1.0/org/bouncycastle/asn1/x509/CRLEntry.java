package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERUTCTime;

public class CRLEntry
    implements DEREncodable
{
    ASN1Sequence  seq;

    DERInteger		userCertificate;
    DERUTCTime		revocationDate;
    X509Extensions	crlEntryExtensions;

    public CRLEntry(
        ASN1Sequence  seq)
    {
        this.seq = seq;

        userCertificate = (DERInteger)seq.getObjectAt(0);
        revocationDate = (DERUTCTime)seq.getObjectAt(1);
        if ( seq.size() == 3 )
        {
            crlEntryExtensions = new X509Extensions((ASN1Sequence)seq.getObjectAt(2));
        }
    }

    public DERInteger getUserCertificate()
    {
        return userCertificate;
    }

    public DERUTCTime getRevocationDate()
    {
        return revocationDate;
    }

    public X509Extensions getExtensions()
    {
        return crlEntryExtensions;
    }

    public DERObject getDERObject()
    {
        return seq;
    }
}
