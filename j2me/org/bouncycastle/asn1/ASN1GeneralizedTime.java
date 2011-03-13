package org.spongycastle.asn1;

public class ASN1GeneralizedTime
    extends DERGeneralizedTime
{
    ASN1GeneralizedTime(byte[] bytes)
    {
        super(bytes);
    }

    public ASN1GeneralizedTime(String time)
    {
        super(time);
    }
}
