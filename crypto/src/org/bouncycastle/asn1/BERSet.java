package org.bouncycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;

public class BERSet
    extends DERSet
{
    public static final BERSet EMPTY = new BERSet();

    public static BERSet fromVector(
        ASN1EncodableVector v)
    {
        return v.size() < 1 ? EMPTY : new BERSet(v);
    }

    static BERSet fromVector(
        ASN1EncodableVector v,
        boolean             needsSorting)
    {
        return v.size() < 1 ? EMPTY : new BERSet(v, needsSorting);
    }

    /**
     * create an empty sequence
     */
    public BERSet()
    {
    }

    /**
     * create a set containing one object
     */
    public BERSet(
        DEREncodable    obj)
    {
        super(obj);
    }

    /**
     * @param v - a vector of objects making up the set.
     */
    public BERSet(
        DEREncodableVector   v)
    {
        super(v, false);
    }

    /**
     * @param v - a vector of objects making up the set.
     */
    BERSet(
        DEREncodableVector   v,
        boolean              needsSorting)
    {
        super(v, needsSorting);
    }

    /*
     */
    void encode(
        DEROutputStream out)
        throws IOException
    {
        if (out instanceof ASN1OutputStream || out instanceof BEROutputStream)
        {
            out.write(SET | CONSTRUCTED);
            out.write(0x80);
            
            Enumeration e = getObjects();
            while (e.hasMoreElements())
            {
                out.writeObject(e.nextElement());
            }
        
            out.write(0x00);
            out.write(0x00);
        }
        else
        {
            super.encode(out);
        }
    }
}
