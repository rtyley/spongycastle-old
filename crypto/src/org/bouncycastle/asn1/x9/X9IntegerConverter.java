package org.bouncycastle.asn1.x9;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;

import java.math.BigInteger;

public class X9IntegerConverter
{
    public int getByteLength(
        ECCurve c)
    {
        return (getFieldSize(c) + 7) / 8;
    }

    public int getByteLength(
        ECFieldElement fe)
    {
        return (getFieldSize(fe) + 7) / 8;
    }

    public int getFieldSize(
        ECCurve c)
    {
        if (c instanceof ECCurve.Fp)
        {
            return ((ECCurve.Fp) c).getQ().bitLength();
        }
        else
        {
            return ((ECCurve.F2m) c).getM();
        }
    }

    public int getFieldSize(
        ECFieldElement fe)
    {
        if (fe instanceof ECFieldElement.Fp)
        {
            return ((ECFieldElement.Fp)fe).getQ().bitLength();
        }
        else
        {
            return ((ECFieldElement.F2m)fe).getM();
        }
    }

    public byte[] integerToBytes(
        BigInteger s,
        int        qLength)
    {
        byte[] bytes = s.toByteArray();
        
        if (qLength < bytes.length)
        {
            byte[] tmp = new byte[qLength];
        
            System.arraycopy(bytes, bytes.length - tmp.length, tmp, 0, tmp.length);
            
            return tmp;
        }
        else if (qLength > bytes.length)
        {
            byte[] tmp = new byte[qLength];
        
            System.arraycopy(bytes, 0, tmp, tmp.length - bytes.length, bytes.length);
            
            return tmp; 
        }
    
        return bytes;
    }
}
