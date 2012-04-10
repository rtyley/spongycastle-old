package org.bouncycastle.asn1.x9;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * ANS.1 def for Diffie-Hellman key exchange OtherInfo structure. See
 * RFC 2631, or X9.42, for further details.
 */
public class OtherInfo
    implements DEREncodable
{
    private KeySpecificInfo     keyInfo;
    private ASN1OctetString     partyAInfo;
    private ASN1OctetString     suppPubInfo;

    public OtherInfo(
        KeySpecificInfo     keyInfo,
        ASN1OctetString     partyAInfo,
        ASN1OctetString     suppPubInfo)
    {
        this.keyInfo = keyInfo;
        this.partyAInfo = partyAInfo;
        this.suppPubInfo = suppPubInfo;
    }

    public OtherInfo(
        ASN1Sequence  seq)
    {
        Enumeration e = seq.getObjects();

        keyInfo = new KeySpecificInfo((ASN1Sequence)e.nextElement());

        while (e.hasMoreElements())
        {
            DERTaggedObject o = (DERTaggedObject)e.nextElement();

            if (o.getTagNo() == 0)
            {
                partyAInfo = (ASN1OctetString)o.getObject();
            }
            else if (o.getTagNo() == 2)
            {
                suppPubInfo = (ASN1OctetString)o.getObject();
            }
        }
    }

    public KeySpecificInfo getKeyInfo()
    {
        return keyInfo;
    }

    public ASN1OctetString getPartyAInfo()
    {
        return partyAInfo;
    }

    public ASN1OctetString getSuppPubInfo()
    {
        return suppPubInfo;
    }

    /**
     * <pre>
     *  OtherInfo ::= SEQUENCE {
     *      keyInfo KeySpecificInfo,
     *      partyAInfo [0] OCTET STRING OPTIONAL,
     *      suppPubInfo [2] OCTET STRING
     *  }
     * </pre>
     */
    public DERObject getDERObject()
    {
        ASN1EncodableVector  seq = new ASN1EncodableVector();

        seq.add(keyInfo);

        if (partyAInfo != null)
        {
            seq.add(new DERTaggedObject(0, partyAInfo));
        }

        seq.add(new DERTaggedObject(2, suppPubInfo));

        return new DERSequence(seq);
    }
}
