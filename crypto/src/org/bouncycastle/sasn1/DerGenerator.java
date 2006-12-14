package org.bouncycastle.sasn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * @deprecated use corresponsding classes in org.bouncycastle.asn1.
 */
public abstract class DerGenerator
    extends Asn1Generator
{       
    private boolean      _tagged = false;
    private boolean      _isExplicit;
    private int          _tagNo;
    
    protected DerGenerator(
        OutputStream out)
    {
        super(out);
    }

    public DerGenerator(
        OutputStream out,
        int          tagNo,
        boolean      isExplicit)
    { 
        super(out);
        
        _tagged = true;
        _isExplicit = isExplicit;
        _tagNo = tagNo;
    }

    private void writeLength(
        OutputStream out,
        int          length)
        throws IOException
    {
        if (length > 127)
        {
            int size = 1;
            int val = length;

            while ((val >>>= 8) != 0)
            {
                size++;
            }

            out.write((byte)(size | 0x80));

            for (int i = (size - 1) * 8; i >= 0; i -= 8)
            {
                out.write((byte)(length >> i));
            }
        }
        else
        {
            out.write((byte)length);
        }
    }

    void writeDerEncoded(
        OutputStream out,
        int          tag,
        byte[]       bytes)
        throws IOException
    {
        out.write(tag);
        writeLength(out, bytes.length);
        out.write(bytes);
    }

    void writeDerEncoded(
        int       tag,
        byte[]    bytes)
        throws IOException
    {
        if (_tagged)
        {
            int tagNum = _tagNo | BerTag.TAGGED;
            
            if (_isExplicit)
            {
                int newTag = _tagNo | BerTag.CONSTRUCTED | BerTag.TAGGED;

                ByteArrayOutputStream bOut = new ByteArrayOutputStream();
                
                writeDerEncoded(bOut, tag, bytes);
                
                writeDerEncoded(_out, newTag, bOut.toByteArray());
            }
            else
            {   
                if ((tag & BerTag.CONSTRUCTED) != 0)
                {
                    writeDerEncoded(_out, tagNum | BerTag.CONSTRUCTED, bytes);
                }
                else
                {
                    writeDerEncoded(_out, tagNum, bytes);
                }
            }
        }
        else
        {
            writeDerEncoded(_out, tag, bytes);
        }
    }
    
    void writeDerEncoded(
        OutputStream out,
        int          tag,
        InputStream  in)
        throws IOException
    {
        out.write(tag);
        
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        int b = 0;
        while ((b = in.read()) >= 0)
        {
            bOut.write(b);
        }
        
        byte[] bytes = bOut.toByteArray();
        
        writeLength(out, bytes.length);
        out.write(bytes);
    }
}
