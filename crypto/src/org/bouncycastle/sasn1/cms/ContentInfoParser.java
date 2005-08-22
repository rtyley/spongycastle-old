package org.bouncycastle.sasn1.cms;

import java.io.IOException;

import org.bouncycastle.sasn1.Asn1Object;
import org.bouncycastle.sasn1.Asn1ObjectIdentifier;
import org.bouncycastle.sasn1.Asn1Sequence;
import org.bouncycastle.sasn1.Asn1TaggedObject;

/**
 * Produce an object suitable for an ASN1OutputStream.
 * <pre>
 * ContentInfo ::= SEQUENCE {
 *          contentType ContentType,
 *          content
 *          [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
 * </pre>
 */
public class ContentInfoParser
{
    private Asn1ObjectIdentifier contentType;
    private Asn1TaggedObject     content;

    public ContentInfoParser(
        Asn1Sequence  seq) 
        throws IOException
    {
        contentType = (Asn1ObjectIdentifier)seq.readObject();
        content = (Asn1TaggedObject)seq.readObject();
    }

    public Asn1ObjectIdentifier getContentType()
    {
        return contentType;
    }

    public Asn1Object getContent(
        int  tag) 
        throws IOException
    {
        return content.getObject(tag, true);
    }
}
