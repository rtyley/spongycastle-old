package org.bouncycastle.asn1.pkcs;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;

public class ContentInfo
    extends ASN1Object
    implements PKCSObjectIdentifiers
{
    private ASN1ObjectIdentifier contentType;
    private ASN1Encodable        content;

    public static ContentInfo getInstance(
        Object  obj)
    {
        if (obj instanceof ContentInfo)
        {
            return (ContentInfo)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new ContentInfo((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public ContentInfo(
        ASN1Sequence  seq)
    {
        Enumeration   e = seq.getObjects();

        contentType = (ASN1ObjectIdentifier)e.nextElement();

        if (e.hasMoreElements())
        {
            content = ((DERTaggedObject)e.nextElement()).getObject();
        }
    }

    public ContentInfo(
        ASN1ObjectIdentifier contentType,
        ASN1Encodable        content)
    {
        this.contentType = contentType;
        this.content = content;
    }

    public ASN1ObjectIdentifier getContentType()
    {
        return contentType;
    }

    public ASN1Encodable getContent()
    {
        return content;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * ContentInfo ::= SEQUENCE {
     *          contentType ContentType,
     *          content
     *          [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(contentType);

        if (content != null)
        {
            v.add(new BERTaggedObject(0, content));
        }

        return new BERSequence(v);
    }
}
