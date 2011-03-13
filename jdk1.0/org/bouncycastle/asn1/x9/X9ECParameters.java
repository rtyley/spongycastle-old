package org.spongycastle.asn1.x9;

import java.math.BigInteger;

import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECCurveFp;
import org.spongycastle.math.ec.ECPoint;

/**
 * ASN.1 def for Elliptic-Curve ECParameters structure. See
 * X9.62, for further details.
 */
public class X9ECParameters
    implements DEREncodable, X9ObjectIdentifiers
{
    private static final BigInteger   ONE = BigInteger.valueOf(1);

    private X9FieldID           fieldID;
    private ECCurve             curve;
    private ECPoint             g;
    private BigInteger          n;
    private BigInteger          h;
    private byte[]              seed;

    public X9ECParameters(
        ASN1Sequence  seq)
    {
        if (!(seq.getObjectAt(0) instanceof DERInteger)
           || !((DERInteger)seq.getObjectAt(0)).getValue().equals(ONE))
        {
            throw new IllegalArgumentException("bad version in X9ECParameters");
        }

        X9Curve     x9c = new X9Curve(
                        new X9FieldID((ASN1Sequence)seq.getObjectAt(1)),
                        (ASN1Sequence)seq.getObjectAt(2));

        this.curve = x9c.getCurve();
        this.g = new X9ECPoint(curve, (ASN1OctetString)seq.getObjectAt(3)).getPoint();
        this.n = ((DERInteger)seq.getObjectAt(4)).getValue();
        this.seed = x9c.getSeed();

        if (seq.size() == 6)
        {
            this.h = ((DERInteger)seq.getObjectAt(5)).getValue();
        }
    }

    public X9ECParameters(
        ECCurve     curve,
        ECPoint     g,
        BigInteger  n)
    {
        this(curve, g, n, ONE, null);
    }

    public X9ECParameters(
        ECCurve     curve,
        ECPoint     g,
        BigInteger  n,
        BigInteger  h)
    {
        this(curve, g, n, h, null);
    }

    public X9ECParameters(
        ECCurve     curve,
        ECPoint     g,
        BigInteger  n,
        BigInteger  h,
        byte[]      seed)
    {
        this.curve = curve;
        this.g = g;
        this.n = n;
        this.h = h;
        this.seed = seed;

        if (curve instanceof ECCurveFp)
        {
            this.fieldID = new X9FieldID(prime_field, ((ECCurveFp)curve).getQ());
        }
        else
        {
            this.fieldID = new X9FieldID(characteristic_two_field, null);
        }
    }

    public ECCurve getCurve()
    {
        return curve;
    }

    public ECPoint getG()
    {
        return g;
    }

    public BigInteger getN()
    {
        return n;
    }

    public BigInteger getH()
    {
        return h;
    }

    public byte[] getSeed()
    {
        return seed;
    }

    /**
     * <pre>
     *  ECParameters ::= SEQUENCE {
     *      version         INTEGER { ecpVer1(1) } (ecpVer1),
     *      fieldID         FieldID {{FieldTypes}},
     *      curve           X9Curve,
     *      base            X9ECPoint,
     *      order           INTEGER,
     *      cofactor        INTEGER OPTIONAL
     *  }
     * </pre>
     */
    public DERObject getDERObject()
    {
        ASN1EncodableVector seq = new ASN1EncodableVector();

        seq.add(new DERInteger(1));
        seq.add(fieldID);
        seq.add(new X9Curve(curve, seed));
        seq.add(new X9ECPoint(g));
        seq.add(new DERInteger(n));

        if (!h.equals(BigInteger.valueOf(1)))
        {
            seq.add(new DERInteger(h));
        }

        return new DERSequence(seq);
    }
}
