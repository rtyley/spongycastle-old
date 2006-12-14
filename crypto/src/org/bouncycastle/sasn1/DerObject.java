package org.bouncycastle.sasn1;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * @deprecated use corresponsding classes in org.bouncycastle.asn1.
 */
public class DerObject
    extends Asn1Object
{
    private byte[] _content;
    
    DerObject(
        int    baseTag,
        int    tagNumber,
        byte[] content)
    {
        super(baseTag, tagNumber, null);
        
        this._content = content;
    }

    public int getTagNumber()
    {
        return _tagNumber;
    }
    
    public InputStream getRawContentStream()
    {
        return new ByteArrayInputStream(_content);
    }
    
    public byte[] getEncoded()
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        this.encode(bOut);

        return bOut.toByteArray();
    }
    
    void encode(
        OutputStream out)
        throws IOException
    {
        DerGenerator dGen = new BasicDerGenerator(out);
        
        dGen.writeDerEncoded(_baseTag | _tagNumber, _content);
    }
    
    private class BasicDerGenerator
        extends DerGenerator
    {
        protected BasicDerGenerator(
            OutputStream out)
        {
            super(out);
        }

        public OutputStream getRawOutputStream()
        {
            return _out;
        }     
    }
}
