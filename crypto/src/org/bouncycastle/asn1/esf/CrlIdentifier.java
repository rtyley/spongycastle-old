package org.bouncycastle.asn1.esf;

import java.math.BigInteger;
import java.text.ParseException;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.X509Name;

/**
 * <pre>
 *  CrlIdentifier ::= SEQUENCE 
 * {
 *   crlissuer    Name,
 *   crlIssuedTime  UTCTime,
 *   crlNumber    INTEGER OPTIONAL
 * }
 * </pre>
 */
public class CrlIdentifier
    extends ASN1Encodable
{
    private X500Name crlIssuer;
    private DERUTCTime crlIssuedTime;
    private DERInteger crlNumber;

    public static CrlIdentifier getInstance(Object obj)
    {
        if (obj instanceof CrlIdentifier)
        {
            return (CrlIdentifier)obj;
        }
        else if (obj != null)
        {
            return new CrlIdentifier(ASN1Sequence.getInstance(obj));
        }

        throw new IllegalArgumentException("null value in getInstance");
    }

    private CrlIdentifier(ASN1Sequence seq)
    {
        if (seq.size() < 2 || seq.size() > 3)
        {
            throw new IllegalArgumentException();
        }
        this.crlIssuer = X500Name.getInstance(seq.getObjectAt(0));
        this.crlIssuedTime = DERUTCTime.getInstance(seq.getObjectAt(1));
        if (seq.size() > 2)
        {
            this.crlNumber = DERInteger.getInstance(seq.getObjectAt(2));
        }
    }

    /**
     * @deprecated use X500Name constructor.
     */
    public CrlIdentifier(X509Name crlIssuer, Date crlIssuedTime)
    {
        this(crlIssuer, crlIssuedTime, null);
    }

    /**
     * @deprecated use X500Name constructor.
     */
    public CrlIdentifier(X509Name crlIssuer, Date crlIssuedTime,
                         BigInteger crlNumber)
    {
        this.crlIssuer = X500Name.getInstance(crlIssuer);
        this.crlIssuedTime = new DERUTCTime(crlIssuedTime);
        if (null != crlNumber)
        {
            this.crlNumber = new DERInteger(crlNumber);
        }
    }

    public CrlIdentifier(X500Name crlIssuer, Date crlIssuedTime)
    {
        this(crlIssuer, crlIssuedTime, null);
    }

    public CrlIdentifier(X500Name crlIssuer, Date crlIssuedTime,
                         BigInteger crlNumber)
    {
        this.crlIssuer = crlIssuer;
        this.crlIssuedTime = new DERUTCTime(crlIssuedTime);
        if (null != crlNumber)
        {
            this.crlNumber = new DERInteger(crlNumber);
        }
    }

    public X500Name getCrlIssuer()
    {
        return this.crlIssuer;
    }

    public Date getCrlIssuedTime()
    {
        try
        {
            return this.crlIssuedTime.getAdjustedDate();
        }
        catch (ParseException e)
        {
            throw new IllegalStateException("invalid date: " + e.getMessage());
        }
    }

    public BigInteger getCrlNumber()
    {
        if (null == this.crlNumber)
        {
            return null;
        }
        return this.crlNumber.getValue();
    }

    public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.crlIssuer.toASN1Object());
        v.add(this.crlIssuedTime);
        if (null != this.crlNumber)
        {
            v.add(this.crlNumber);
        }
        return new DERSequence(v);
    }

}
