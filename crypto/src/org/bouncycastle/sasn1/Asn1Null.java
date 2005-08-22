package org.bouncycastle.sasn1;

public class Asn1Null
    extends Asn1Object
{
    protected Asn1Null(
        int baseTag)
    {
        super(baseTag, BerTag.NULL, null);
    }
}
