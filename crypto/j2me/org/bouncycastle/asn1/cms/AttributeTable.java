package org.bouncycastle.asn1.cms;

import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEREncodableVector;

public class AttributeTable
{
    private Hashtable attributes = new Hashtable();

    public AttributeTable(
        Hashtable  attrs)
    {
        attributes = attrs;
    }

    public AttributeTable(
        DEREncodableVector v)
    {
        for (int i = 0; i != v.size(); i++)
        {
            Attribute   a = Attribute.getInstance(v.get(i));

            attributes.put(a.getAttrType(), a);
        }
    }

    public AttributeTable(
        ASN1Set    s)
    {
        for (int i = 0; i != s.size(); i++)
        {
            Attribute   a = Attribute.getInstance(s.getObjectAt(i));

            attributes.put(a.getAttrType(), a);
        }
    }

    public Attribute get(
        DERObjectIdentifier oid)
    {
        return (Attribute)attributes.get(oid);
    }

    public Hashtable toHashtable()
    {
        return attributes;
    }
}
