package org.bouncycastle.cms;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;

import java.util.Date;
import java.util.Hashtable;
import java.util.Map;

/**
 * Default signed attributes generator.
 */
public class DefaultSignedAttributeTableGenerator
    implements CMSAttributeTableGenerator
{
    private final Hashtable table;

    /**
     * Initialise to use all defaults
     */
    public DefaultSignedAttributeTableGenerator()
    {
        table = new Hashtable();
    }

    /**
     * Initialise with some extra attributes or overrides.
     *
     * @param attributeTable initial attribute table to use.
     */
    public DefaultSignedAttributeTableGenerator(
        AttributeTable attributeTable)
    {
        if (attributeTable != null)
        {
            table = attributeTable.toHashtable();
        }
        else
        {
            table = new Hashtable();
        }
    }

    /**
     * Create a standard attribute table from the passed in parameters - this will
     * normally include contentType, signingTime, and messageDigest. If the constructor
     * using an AttributeTable was used, entries in it for contentType, signingTime, and
     * messageDigest will override the generated ones.
     *
     * @param parameters source parameters for table generation.
     *
     * @return a filled in Hashtable of attributes.
     */
    protected Hashtable createStandardAttributeTable(
        Map parameters)
    {
        Hashtable std = (Hashtable)table.clone();

        if (table.containsKey(CMSAttributes.contentType))
        {
            std.put(CMSAttributes.contentType, table.get(CMSAttributes.contentType));
        }
        else
        {
            Attribute attr = new Attribute(CMSAttributes.contentType,
                              new DERSet((DERObjectIdentifier)parameters.get(CMSAttributeTableGenerator.CONTENT_TYPE)));
            std.put(attr.getAttrType(), attr);
        }

        if (table.containsKey(CMSAttributes.signingTime))
        {
            std.put(CMSAttributes.signingTime, table.get(CMSAttributes.signingTime));
        }
        else
        {
            Attribute attr = new Attribute(CMSAttributes.signingTime, new DERSet(new Time(new Date())));
            std.put(attr.getAttrType(), attr);
        }

        if (table.containsKey(CMSAttributes.messageDigest))
        {
            std.put(CMSAttributes.messageDigest, table.get(CMSAttributes.messageDigest));
        }
        else
        {
            byte[] hash = (byte[])parameters.get(CMSAttributeTableGenerator.DIGEST);
            Attribute attr;

            if (hash != null)
            {
                attr = new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(hash)));
            }
            else
            {
                attr = new Attribute(CMSAttributes.messageDigest, new DERSet(new DERNull()));
            }

            std.put(attr.getAttrType(), attr);
        }

        return std;
    }

    /**
     * @param parameters source parameters
     * @return the populated attribute table
     */
    public AttributeTable getAttributes(Map parameters)
    {
        return new AttributeTable(createStandardAttributeTable(parameters));
    }
}
