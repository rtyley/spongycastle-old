package org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;

public class DERSequence
    extends ASN1Sequence
{
    /**
     * create an empty sequence
     */
    public DERSequence()
    {
    }

    /**
     * create a sequence containing one object
     */
    public DERSequence(
        ASN1Encodable obj)
    {
        super(obj);
    }

    /**
     * create a sequence containing a vector of objects.
     */
    public DERSequence(
        ASN1EncodableVector v)
    {
        super(v);
    }

    /**
     * create a sequence containing an array of objects.
     */
    public DERSequence(
        ASN1Encodable[]   array)
    {
        super(array);
    }
    
    /*
     * A note on the implementation:
     * <p>
     * As DER requires the constructed, definite-length model to
     * be used for structured types, this varies slightly from the
     * ASN.1 descriptions given. Rather than just outputting SEQUENCE,
     * we also have to specify CONSTRUCTED, and the objects length.
     */
    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        // TODO Intermediate buffer could be avoided if we could calculate expected length
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        DEROutputStream         dOut = new DEROutputStream(bOut);
        Enumeration             e = this.getObjects();

        while (e.hasMoreElements())
        {
            Object    obj = e.nextElement();

            dOut.writeObject((ASN1Encodable)obj);
        }

        dOut.close();

        byte[]  bytes = bOut.toByteArray();

        out.writeEncoded(BERTags.SEQUENCE | BERTags.CONSTRUCTED, bytes);
    }
}
