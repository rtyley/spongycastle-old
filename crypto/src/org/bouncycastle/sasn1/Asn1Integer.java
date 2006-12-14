package org.bouncycastle.sasn1;

import java.io.IOException;
import java.math.BigInteger;

/**
 * @deprecated use corresponsding classes in org.bouncycastle.asn1.
 */
public class Asn1Integer
    extends DerObject
{
    private BigInteger _value;
    
    protected Asn1Integer(
        int                baseTag,
        byte[]             data)
        throws IOException
    {
        super(baseTag, BerTag.INTEGER, data);
        
        this._value = new BigInteger(data);
    }

    public Asn1Integer(
        long value)
    {
        this(BigInteger.valueOf(value));
    }
    
    public Asn1Integer(
        BigInteger value)
    {
        super(BerTagClass.UNIVERSAL, BerTag.INTEGER, value.toByteArray());
        
        this._value = value;
    }

    public BigInteger getValue()
    {
        return _value;
    }
}
