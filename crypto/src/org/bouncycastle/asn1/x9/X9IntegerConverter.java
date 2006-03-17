package org.bouncycastle.asn1.x9;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;

public class X9IntegerConverter
{
    public int getByteLength(
        ECFieldElement fe)
    {
        if (fe instanceof ECFieldElement.Fp)
        {
            ECFieldElement.Fp ep = (ECFieldElement.Fp)fe;
            
            return (ep.getQ().bitLength() + 7) / 8;
        }
        else
        {
            ECFieldElement.F2m em = (ECFieldElement.F2m)fe;
            
            return (em.getM() + 7) / 8;
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
