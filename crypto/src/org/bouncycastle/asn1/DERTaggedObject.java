package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * DER TaggedObject - in ASN.1 notation this is any object preceded by
 * a [n] where n is some number - these are assumed to follow the construction
 * rules (as with sequences).
 */
public class DERTaggedObject
    extends ASN1TaggedObject
{
    private static final byte[] ZERO_BYTES = new byte[0];

    /**
     * @param explicit true if an explicitly tagged object.
     * @param tagNo the tag number for this object.
     * @param obj the tagged object.
     */
    public DERTaggedObject(
        boolean       explicit,
        int           tagNo,
        ASN1Encodable obj)
    {
        super(explicit, tagNo, obj);
    }

    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        if (!empty)
        {
            byte[] bytes = obj.toASN1Primitive().getEncoded(ASN1Encoding.DER);

            if (explicit)
            {
                out.writeEncoded(BERTags.CONSTRUCTED | BERTags.TAGGED, tagNo, bytes);
            }
            else
            {
                //
                // need to mark constructed types...
                //
                int flags;
                if ((bytes[0] & BERTags.CONSTRUCTED) != 0)
                {
                    flags = BERTags.CONSTRUCTED | BERTags.TAGGED;
                }
                else
                {
                    flags = BERTags.TAGGED;
                }

                out.writeTag(flags, tagNo);
                out.write(bytes, 1, bytes.length - 1);
            }
        }
        else
        {
            out.writeEncoded(BERTags.CONSTRUCTED | BERTags.TAGGED, tagNo, ZERO_BYTES);
        }
    }
}
