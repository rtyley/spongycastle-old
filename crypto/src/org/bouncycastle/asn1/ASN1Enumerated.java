package org.bouncycastle.asn1;

import java.math.BigInteger;

import org.bouncycastle.util.Arrays;

public class ASN1Enumerated
    extends DEREnumerated
{
    ASN1Enumerated(byte[] bytes)
    {
        super(bytes);
    }

    public ASN1Enumerated(BigInteger value)
    {
        super(value);
    }

    public ASN1Enumerated(int value)
    {
        super(value);
    }

    private static ASN1Enumerated[] cache = new ASN1Enumerated[12];

    static ASN1Enumerated fromOctetString(byte[] enc)
    {
        if (enc.length > 1)
        {
            return new ASN1Enumerated(enc);
        }

        int value = enc[0] & 0xff;

        if (value >= cache.length)
        {
            return new ASN1Enumerated(enc);
        }

        ASN1Enumerated possibleMatch = cache[value];

        if (possibleMatch == null)
        {
            possibleMatch = cache[value] = new ASN1Enumerated(Arrays.clone(enc));
        }

        return possibleMatch;
    }
}
