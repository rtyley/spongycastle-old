package org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;

/**
 * A DER encoded set object
 */
public class DLSet
    extends ASN1Set
{
    /**
     * create an empty set
     */
    public DLSet()
    {
    }

    /**
     * @param obj - a single object that makes up the set.
     */
    public DLSet(
        ASN1Encodable obj)
    {
        super(obj);
    }

    /**
     * @param v - a vector of objects making up the set.
     */
    public DLSet(
        ASN1EncodableVector v)
    {
        super(v, false);
    }

    /**
     * create a set from an array of objects.
     */
    public DLSet(
        ASN1Encodable[] a)
    {
        super(a, false);
    }

    /*
     * A note on the implementation:
     * <p>
     * As DER requires the constructed, definite-length model to
     * be used for structured types, this varies slightly from the
     * ASN.1 descriptions given. Rather than just outputting SET,
     * we also have to specify CONSTRUCTED, and the objects length.
     */
    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        // TODO Intermediate buffer could be avoided if we could calculate expected length
        ByteArrayOutputStream  bOut = new ByteArrayOutputStream();
        DLOutputStream         dOut = new DLOutputStream(bOut);
        Enumeration            e = this.getObjects();

        while (e.hasMoreElements())
        {
            Object    obj = e.nextElement();

            dOut.writeObject((ASN1Encodable)obj);
        }

        dOut.close();

        byte[]  bytes = bOut.toByteArray();

        out.writeEncoded(BERTags.SET | BERTags.CONSTRUCTED, bytes);
    }
}
