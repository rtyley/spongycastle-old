package org.spongycastle.asn1;

public class ASN1UTCTime
    extends DERUTCTime
{
    ASN1UTCTime(byte[] bytes)
    {
        super(bytes);
    }

    public ASN1UTCTime(String time)
    {
        super(time);
    }
}
