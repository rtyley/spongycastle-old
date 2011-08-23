package org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;

public class DLSequence
    extends ASN1Sequence
{
    /**
     * create an empty sequence
     */
    public DLSequence()
    {
    }

    /**
     * create a sequence containing one object
     */
    public DLSequence(
        ASN1Encodable obj)
    {
        addObject(obj);
    }

    /**
     * create a sequence containing a vector of objects.
     */
    public DLSequence(
        ASN1EncodableVector v)
    {
        for (int i = 0; i != v.size(); i++)
        {
            this.addObject(v.get(i));
        }
    }
    
    /*
     * A note on the implementation:
     * <p>
     * As DER requires the constructed, definite-length model to
     * be used for structured types, this varies slightly from the
     * ASN.1 descriptions given. Rather than just outputting SEQUENCE,
     * we also have to specify CONSTRUCTED, and the objects length.
     */
    void encode(DEROutputStream out)
        throws IOException
    {
                // TODO Intermediate buffer could be avoided if we could calculate expected length
        if (out instanceof ASN1OutputStream)
        {
            ByteArrayOutputStream  bOut = new ByteArrayOutputStream();
            ASN1OutputStream       dOut = new ASN1OutputStream(bOut);
            Enumeration            e = this.getObjects();

            while (e.hasMoreElements())
            {
                Object    obj = e.nextElement();

                dOut.writeObject((ASN1Encodable)obj);
            }

            dOut.close();

            byte[]  bytes = bOut.toByteArray();

            out.writeEncoded(BERTags.SEQUENCE | BERTags.CONSTRUCTED, bytes);
        }
        else
        {
            ByteArrayOutputStream  bOut = new ByteArrayOutputStream();
            DEROutputStream         dOut = new DEROutputStream(bOut);
            Enumeration            e = this.getObjects();

            while (e.hasMoreElements())
            {
                Object    obj = e.nextElement();

                dOut.writeObject(obj);
            }

            dOut.close();

            byte[]  bytes = bOut.toByteArray();

            out.writeEncoded(BERTags.SEQUENCE | BERTags.CONSTRUCTED, bytes);
        }
    }
}
