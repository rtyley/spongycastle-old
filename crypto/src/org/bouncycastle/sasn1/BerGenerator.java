package org.bouncycastle.sasn1;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * @deprecated use corresponsding classes in org.bouncycastle.asn1.
 */
public class BerGenerator
    extends Asn1Generator
{
    private boolean      _tagged = false;
    private boolean      _isExplicit;
    private int          _tagNo;
    
    protected BerGenerator(
        OutputStream out)
    {
        super(out);
    }

    public BerGenerator(
        OutputStream out,
        int tagNo,
        boolean isExplicit) 
    {
        super(out);
        
        _tagged = true;
        _isExplicit = isExplicit;
        _tagNo = tagNo;
    }

    public OutputStream getRawOutputStream()
    {
        return _out;
    }
    
    private void writeHdr(
        int tag)
        throws IOException
    {
        _out.write(tag);
        _out.write(0x80);
    }
    
    protected void writeBerHeader(
        int tag) 
        throws IOException
    {
        int tagNum = _tagNo | BerTag.TAGGED;
        
        if (_tagged)
        {
            if (_isExplicit)
            {
                writeHdr(tagNum | BerTag.CONSTRUCTED);
                writeHdr(tag);
            }
            else
            {   
                if ((tag & BerTag.CONSTRUCTED) != 0)
                {
                    writeHdr(tagNum | BerTag.CONSTRUCTED);
                }
                else
                {
                    writeHdr(tagNum);
                }
            }
        }
        else
        {
            writeHdr(tag);
        }
    }
    
    protected void writeBerBody(
        InputStream contentStream)
        throws IOException
    {
        int ch;
        
        while ((ch = contentStream.read()) >= 0)
        {
            _out.write(ch);
        }
    }

    protected void writeBerEnd()
        throws IOException
    {
        _out.write(0x00);
        _out.write(0x00);
        
        if (_tagged && _isExplicit)  // write extra end for tag header
        {
            _out.write(0x00);
            _out.write(0x00);
        }
    }
}
