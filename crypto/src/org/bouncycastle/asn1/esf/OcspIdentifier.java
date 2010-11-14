package org.bouncycastle.asn1.esf;

import java.text.ParseException;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.ResponderID;

/**
 * <pre>
 * OcspIdentifier ::= SEQUENCE {
 *     ocspResponderID ResponderID, -- As in OCSP response data
 *     producedAt GeneralizedTime -- As in OCSP response data
 * }
 * </pre>
 */
public class OcspIdentifier
    extends ASN1Encodable
{

    private ResponderID ocspResponderID;
    private DERGeneralizedTime producedAt;

    public static OcspIdentifier getInstance(Object obj)
    {
        if (obj instanceof OcspIdentifier)
        {
            return (OcspIdentifier)obj;
        }
        else if (obj != null)
        {
            return new OcspIdentifier(ASN1Sequence.getInstance(obj));
        }

        throw new IllegalArgumentException("null value in getInstance");
    }

    private OcspIdentifier(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                + seq.size());
        }
        this.ocspResponderID = ResponderID.getInstance(seq.getObjectAt(0));
        this.producedAt = (DERGeneralizedTime)seq.getObjectAt(1);
    }

    public OcspIdentifier(ResponderID ocspResponderID, Date producedAt)
    {
        this.ocspResponderID = ocspResponderID;
        this.producedAt = new DERGeneralizedTime(producedAt);
    }

    public ResponderID getOcspResponderID()
    {
        return this.ocspResponderID;
    }

    public Date getProducedAt()
    {
        try
        {
            return this.producedAt.getDate();
        }
        catch (ParseException e)
        {
            throw new IllegalStateException("date parse error: "
                + e.getMessage());
        }
    }

    public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.ocspResponderID);
        v.add(this.producedAt);
        return new DERSequence(v);
    }
}
