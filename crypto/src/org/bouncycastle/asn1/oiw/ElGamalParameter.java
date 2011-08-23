package org.bouncycastle.asn1.oiw;

import java.math.BigInteger;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;

public class ElGamalParameter
    extends ASN1Object
{
    DERInteger      p, g;

    public ElGamalParameter(
        BigInteger  p,
        BigInteger  g)
    {
        this.p = new DERInteger(p);
        this.g = new DERInteger(g);
    }

    public ElGamalParameter(
        ASN1Sequence  seq)
    {
        Enumeration     e = seq.getObjects();

        p = (DERInteger)e.nextElement();
        g = (DERInteger)e.nextElement();
    }

    public BigInteger getP()
    {
        return p.getPositiveValue();
    }

    public BigInteger getG()
    {
        return g.getPositiveValue();
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(p);
        v.add(g);

        return new DERSequence(v);
    }
}
