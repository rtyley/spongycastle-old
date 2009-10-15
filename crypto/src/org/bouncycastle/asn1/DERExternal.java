package org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Class representing the DER-type External
 */
public class DERExternal
    extends ASN1Object
{
    private DERObjectIdentifier directReferemce;
    private DERInteger indirectReference;
    private ASN1Object dataValueDescriptor;
    private int encoding;
    private DERObject externalContent;
    
    public DERExternal(ASN1EncodableVector vector)
    {
        int offset = 0;
        DERObject enc = vector.get(offset).getDERObject();
        if (enc instanceof DERObjectIdentifier)
        {
            directReferemce = (DERObjectIdentifier)enc;
            offset++;
            enc = vector.get(offset).getDERObject();
        }
        if (enc instanceof DERInteger)
        {
            indirectReference = (DERInteger) enc;
            offset++;
            enc = vector.get(offset).getDERObject();
        }
        if (!(enc instanceof DERTaggedObject))
        {
            dataValueDescriptor = (ASN1Object) enc;
            offset++;
            enc = vector.get(offset).getDERObject();
        }
        if (!(enc instanceof DERTaggedObject))
        {
            throw new IllegalArgumentException("No tagged object found in vector. Structure doesn't seem to be of type External");
        }
        DERTaggedObject obj = (DERTaggedObject)enc;
        setEncoding(obj.getTagNo());
        externalContent = obj.getDERObject();
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    public int hashCode()
    {
        int ret = 0;
        if (directReferemce != null)
        {
            ret = directReferemce.hashCode();
        }
        if (indirectReference != null)
        {
            ret ^= indirectReference.hashCode();
        }
        if (dataValueDescriptor != null)
        {
            ret ^= dataValueDescriptor.hashCode();
        }
        ret ^= externalContent.hashCode();
        return ret;
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.DERObject#encode(org.bouncycastle.asn1.DEROutputStream)
     */
    void encode(DEROutputStream out)
        throws IOException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        if (directReferemce != null)
        {
            baos.write(directReferemce.getDEREncoded());
        }
        if (indirectReference != null)
        {
            baos.write(indirectReference.getDEREncoded());
        }
        if (dataValueDescriptor != null)
        {
            baos.write(dataValueDescriptor.getDEREncoded());
        }
        DERTaggedObject obj = new DERTaggedObject(DERTags.EXTERNAL, externalContent);
        baos.write(obj.getDEREncoded());
        out.writeEncoded(DERTags.CONSTRUCTED, DERTags.EXTERNAL, baos.toByteArray());
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Object#asn1Equals(org.bouncycastle.asn1.DERObject)
     */
    boolean asn1Equals(DERObject o)
    {
        if (!(o instanceof DERExternal))
        {
            return false;
        }
        if (this == o)
        {
            return true;
        }
        DERExternal other = (DERExternal)o;
        if (directReferemce != null)
        {
            if (other.directReferemce == null || !other.directReferemce.equals(directReferemce))  
            {
                return false;
            }
        }
        if (indirectReference != null)
        {
            if (other.indirectReference == null || !other.indirectReference.equals(indirectReference))
            {
                return false;
            }
        }
        if (dataValueDescriptor != null)
        {
            if (other.dataValueDescriptor == null || !other.dataValueDescriptor.equals(dataValueDescriptor))
            {
                return false;
            }
        }
        return externalContent.equals(other.externalContent);
    }

    /**
     * Returns the data value descriptor
     * @return The descriptor
     */
    public ASN1Object getDataValueDescriptor()
    {
        return dataValueDescriptor;
    }

    /**
     * Returns the direct reference of the external element
     * @return The reference
     */
    public DERObjectIdentifier getDirectReferemce()
    {
        return directReferemce;
    }

    /**
     * Returns the encoding of the content. Valid values are
     * <ul>
     * <li><code>0</code> single-ASN1-type</li>
     * <li><code>1</code> OCTET STRING</li>
     * <li><code>2</code> BIT STRING</li>
     * </ul>
     * @return The encoding
     */
    public int getEncoding()
    {
        return encoding;
    }
    
    /**
     * Returns the content of this element
     * @return The content
     */
    public DERObject getExternalContent()
    {
        return externalContent;
    }
    
    /**
     * Returns the indirect reference of this element
     * @return The reference
     */
    public DERInteger getIndirectReference()
    {
        return indirectReference;
    }
    
    /**
     * Sets the data value descriptor
     * @param dataValueDescriptor The descriptor
     */
    private void setDataValueDescriptor(ASN1Object dataValueDescriptor)
    {
        this.dataValueDescriptor = dataValueDescriptor;
    }

    /**
     * Sets the direct reference of the external element
     * @param directReferemce The reference
     */
    private void setDirectReferemce(DERObjectIdentifier directReferemce)
    {
        this.directReferemce = directReferemce;
    }
    
    /**
     * Sets the encoding of the content. Valid values are
     * <ul>
     * <li><code>0</code> single-ASN1-type</li>
     * <li><code>1</code> OCTET STRING</li>
     * <li><code>2</code> BIT STRING</li>
     * </ul>
     * @param encoding The encoding
     */
    private void setEncoding(int encoding)
    {
        if (encoding < 0 || encoding > 2)
        {
            throw new IllegalArgumentException("invalid encoding value");
        }
        this.encoding = encoding;
    }
    
    /**
     * Sets the content of this element
     * @param externalContent The content
     */
    private void setExternalContent(DERObject externalContent)
    {
        this.externalContent = externalContent;
    }
    
    /**
     * Sets the indirect reference of this element
     * @param indirectReference The reference
     */
    private void setIndirectReference(DERInteger indirectReference)
    {
        this.indirectReference = indirectReference;
    }
}
