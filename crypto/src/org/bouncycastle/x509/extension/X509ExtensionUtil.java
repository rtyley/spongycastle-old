package org.bouncycastle.x509.extension;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;

import java.io.IOException;


public class X509ExtensionUtil
{
    public static ASN1Encodable fromExtensionValue(
        byte[]  encodedValue) 
        throws IOException
    {
        ASN1OctetString octs = (ASN1OctetString)ASN1Object.fromByteArray(encodedValue);
        
        return (ASN1Encodable)ASN1Object.fromByteArray(octs.getOctets());
    }
}
