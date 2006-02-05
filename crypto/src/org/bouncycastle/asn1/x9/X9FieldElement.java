package org.bouncycastle.asn1.x9;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECFieldElement.F2m;

/**
 * class for processing an FieldElement as a DER object.
 */
public class X9FieldElement
    extends ASN1Encodable
{
    protected ECFieldElement  f;
    
    private static X9IntegerConverter converter = new X9IntegerConverter();

    public X9FieldElement(ECFieldElement f)
    {
        this.f = f;
    }
    
    public X9FieldElement(BigInteger p, ASN1OctetString s)
    {
        this(new ECFieldElement.Fp(p, new BigInteger(1, s.getOctets())));
    }
    
    public X9FieldElement(int m, int k1, int k2, int k3, ASN1OctetString s)
    {
        this(new ECFieldElement.F2m(m, k1, k2, k3, new BigInteger(1, s.getOctets())));
    }
    
    public ECFieldElement getValue()
    {
        return f;
    }

    private byte[] mToByteArray(
        int m)
    {
        byte[] v;
        
        if (m > 0xff)
        {
            if (m > 0xffff)
            {
                if (m > 0xffffff)
                {
                    v = new byte[4];
                    
                    v[3] = (byte)(m >> 24);
                } 
                else
                {
                    v = new byte[3];
                }
                    
                v[2] = (byte)(m >> 16);
            } 
            else
            {
                v = new byte[2];
            }
                
            v[1] = (byte)(m >> 8);
        }
        else
        {
            v = new byte[1];
        }
        
        v[0] = (byte)m;
        
        return v;
    }
    
    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     *  FieldElement ::= OCTET STRING
     * </pre>
     * <p>
     * <ol>
     * <li> if <i>q</i> is an odd prime then the field element is
     * processed as an Integer and converted to an octet string
     * according to x 9.62 4.3.1.</li>
     * <li> if <i>q</i> is 2<sup>m</sup> then the bit string
     * contained in the field element is converted into an octet
     * string with the same ordering padded at the front if necessary.
     * </li>
     * </ol>
     */
    public DERObject toASN1Object()
    {
        if (f instanceof ECFieldElement.Fp)
        {
            BigInteger q = ((ECFieldElement.Fp)f).getQ();
            int byteCount = converter.getQLength(q);
            byte[] paddedBigInteger = converter.integerToBytes(f.toBigInteger(), byteCount);
    
            return new DEROctetString(paddedBigInteger);
        }
        else
        {
            ECFieldElement.F2m element = (F2m)f;
            
            return new DEROctetString(mToByteArray(element.getM()));
        }
    }
}
