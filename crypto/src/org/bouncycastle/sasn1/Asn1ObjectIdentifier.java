package org.bouncycastle.sasn1;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;

/**
 * @deprecated use corresponsding classes in org.bouncycastle.asn1.
 */
public class Asn1ObjectIdentifier
    extends DerObject
{
    private String  _oid;
    
    Asn1ObjectIdentifier(
        int    baseTag,
        byte[] data) 
        throws IOException
    {
        super(baseTag, BerTag.OBJECT_IDENTIFIER, data);

        StringBuffer    objId = new StringBuffer();
        long            value = 0;
        boolean         first = true;
        int             b = 0;
        BigInteger           bigValue = null;
        ByteArrayInputStream bIn = new ByteArrayInputStream(data);
        
        while ((b = bIn.read()) >= 0)
        {
            if (value < 0x80000000000000L) 
            {
                value = value * 128 + (b & 0x7f);
                if ((b & 0x80) == 0)             // end of number reached
                {
                    if (first)
                    {
                        switch ((int)value / 40)
                        {
                        case 0:
                            objId.append('0');
                            break;
                        case 1:
                            objId.append('1');
                            value -= 40;
                            break;
                        default:
                            objId.append('2');
                            value -= 80;
                        }
                        first = false;
                    }

                    objId.append('.');
                    objId.append(value);
                    value = 0;
                }
            } 
            else 
            {
                if (bigValue == null)
                {
                    bigValue = BigInteger.valueOf(value);
                }
                bigValue = bigValue.shiftLeft(7);
                bigValue = bigValue.or(BigInteger.valueOf(b & 0x7f));
                if ((b & 0x80) == 0) 
                {
                    objId.append('.');
                    objId.append(bigValue);
                    bigValue = null;
                    value = 0;
                }
            }
        }

        this._oid = objId.toString();
    }
    
    public Asn1ObjectIdentifier(
        String oid)
        throws IllegalArgumentException
    {
        super(BerTagClass.UNIVERSAL, BerTag.OBJECT_IDENTIFIER, toByteArray(oid));
        
        this._oid = oid;
    }

    public String toString()
    {
        return _oid;
    }
    
    public int hashCode()
    {
        return _oid.hashCode();
    }

    public boolean equals(
        Object  o)
    {
        if (!(o instanceof Asn1ObjectIdentifier))
        {
            return false;
        }

        return _oid.equals(((Asn1ObjectIdentifier)o)._oid);
    }
    
    private static void writeField(
        OutputStream    out,
        long            fieldValue)
        throws IOException
    {
        if (fieldValue >= (1L << 7))
        {
            if (fieldValue >= (1L << 14))
            {
                if (fieldValue >= (1L << 21))
                {
                    if (fieldValue >= (1L << 28))
                    {
                        if (fieldValue >= (1L << 35))
                        {
                            if (fieldValue >= (1L << 42))
                            {
                                if (fieldValue >= (1L << 49))
                                {
                                    if (fieldValue >= (1L << 56))
                                    {
                                        out.write((int)(fieldValue >> 56) | 0x80);
                                    }
                                    out.write((int)(fieldValue >> 49) | 0x80);
                                }
                                out.write((int)(fieldValue >> 42) | 0x80);
                            }
                            out.write((int)(fieldValue >> 35) | 0x80);
                        }
                        out.write((int)(fieldValue >> 28) | 0x80);
                    }
                    out.write((int)(fieldValue >> 21) | 0x80);
                }
                out.write((int)(fieldValue >> 14) | 0x80);
            }
            out.write((int)(fieldValue >> 7) | 0x80);
        }
        out.write((int)fieldValue & 0x7f);
    }

    private static void writeField(
        OutputStream    out,
        BigInteger      fieldValue)
        throws IOException
    {
        int byteCount = (fieldValue.bitLength()+6)/7;
        if (byteCount == 0) 
        {
            out.write(0);
        }  
        else 
        {
            BigInteger tmpValue = fieldValue;
            byte[] tmp = new byte[byteCount];
            for (int i = byteCount-1; i >= 0; i--) 
            {
                tmp[i] = (byte) ((tmpValue.intValue() & 0x7f) | 0x80);
                tmpValue = tmpValue.shiftRight(7); 
            }
            tmp[byteCount-1] &= 0x7f;
            out.write(tmp);
        }

    }
    
    private static byte[] toByteArray(
        String oid) 
        throws IllegalArgumentException
    {
        OIDTokenizer            tok = new OIDTokenizer(oid);
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();

        try
        {
            writeField(bOut, 
                        Integer.parseInt(tok.nextToken()) * 40
                        + Integer.parseInt(tok.nextToken()));
        
            while (tok.hasMoreTokens())
            {
                String token = tok.nextToken();
                if (token.length() < 18) 
                {
                    writeField(bOut, Long.parseLong(token));
                }
                else
                {
                    writeField(bOut, new BigInteger(token));
                }
            }
        }
        catch (NumberFormatException e)
        {
            throw new IllegalArgumentException("exception parsing field value: " + e.getMessage());
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("exception converting to bytes: " + e.getMessage());
        }

        return bOut.toByteArray();
    }
    
    private static class OIDTokenizer
    {
        private String  oid;
        private int     index;

        public OIDTokenizer(
            String oid)
        {
            this.oid = oid;
            this.index = 0;
        }

        public boolean hasMoreTokens()
        {
            return (index != -1);
        }

        public String nextToken()
        {
            if (index == -1)
            {
                return null;
            }

            String  token;
            int     end = oid.indexOf('.', index);

            if (end == -1)
            {
                token = oid.substring(index);
                index = -1;
                return token;
            }

            token = oid.substring(index, end);

            index = end + 1;
            return token;
        }
    }
}
