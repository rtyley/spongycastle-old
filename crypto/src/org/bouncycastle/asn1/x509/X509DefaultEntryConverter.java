package org.bouncycastle.asn1.x509;

import java.io.IOException;

import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * The default converter for X509 DN entries when going from their
 * string value to 
 */
public class X509DefaultEntryConverter
    extends X509NameEntryConverter
{
    /**
     * Apply default coversion for the given value depending on the oid
     * and the character range of the value.
     * 
     * @param oid the object identifier for the DN entry
     * @param value the value associated with it
     * @return the ASN.1 equivalent for the string value.
     */
    public DERObject getConvertedValue(
        DERObjectIdentifier  oid,
        String               value)
    {
        if (value.length() != 0 && value.charAt(0) == '#')
        {
            try
            {
                return convertHexEncoded(value, 1);
            }
            catch (IOException e)
            {
                throw new RuntimeException("can't recode value for oid " + oid.getId());
            }
        }
        else if (oid.equals(X509Name.EmailAddress))
        {
            return new DERIA5String(value);
        }
        else if (canBePrintable(value))  
        {
            return new DERPrintableString(value);
        }
        else if (canBeUTF8(value))
        {
            return new DERUTF8String(value);
        }

        return new DERBMPString(value);
    }
}
