package org.spongycastle.asn1.cmp;

import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERSequence;

public class PollRepContent
    extends ASN1Object
{
    private ASN1Integer certReqId;
    private ASN1Integer checkAfter;
    private PKIFreeText reason;

    private PollRepContent(ASN1Sequence seq)
    {
        certReqId = ASN1Integer.getInstance(seq.getObjectAt(0));
        checkAfter = ASN1Integer.getInstance(seq.getObjectAt(1));

        if (seq.size() > 2)
        {
            reason = PKIFreeText.getInstance(seq.getObjectAt(2));
        }
    }

    public static PollRepContent getInstance(Object o)
    {
        if (o instanceof PollRepContent)
        {
            return (PollRepContent)o;
        }

        if (o != null)
        {
            return new PollRepContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1Integer getCertReqId()
    {
        return certReqId;
    }

    public ASN1Integer getCheckAfter()
    {
        return checkAfter;
    }

    public PKIFreeText getReason()
    {
        return reason;
    }

    /**
     * <pre>
     * PollRepContent ::= SEQUENCE OF SEQUENCE {
     *         certReqId              INTEGER,
     *         checkAfter             INTEGER,  -- time in seconds
     *         reason                 PKIFreeText OPTIONAL
     *     }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(certReqId);
        v.add(checkAfter);

        if (reason != null)
        {
            v.add(reason);
        }
        
        return new DERSequence(v);
    }
}
