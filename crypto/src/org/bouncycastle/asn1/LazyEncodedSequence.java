package org.bouncycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;

class LazyEncodedSequence
    extends ASN1Sequence
{
    private byte[] encoded;
    private boolean parsed = false;
    private int size = -1;

    LazyEncodedSequence(
        byte[] encoded)
        throws IOException
    {
        this.encoded = encoded;
    }

    private void parse()
    {
        Enumeration en = new LazyConstructionEnumeration(encoded);

        while (en.hasMoreElements())
        {
            seq.addElement(en.nextElement());
        }

        parsed = true;
    }

    public synchronized ASN1Encodable getObjectAt(int index)
    {
        if (!parsed)
        {
            parse();
        }

        return super.getObjectAt(index);
    }

    public synchronized Enumeration getObjects()
    {
        if (parsed)
        {
            return super.getObjects();
        }

        return new LazyConstructionEnumeration(encoded);
    }

    public synchronized int size()
    {
        if (!parsed)
        {
            parse();
        }

        return super.size();
    }

    ASN1Primitive toDERObject()
    {
        if (!parsed)
        {
            parse();
        }

        return super.toDERObject();
    }

    ASN1Primitive toDLObject()
    {
        if (!parsed)
        {
            parse();
        }

        return super.toDLObject();
    }

    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(encoded.length) + encoded.length;
    }

    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        out.writeEncoded(BERTags.SEQUENCE | BERTags.CONSTRUCTED, encoded);
    }
}
