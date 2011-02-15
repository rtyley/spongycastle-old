package org.bouncycastle.asn1;

import java.util.Date;

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
