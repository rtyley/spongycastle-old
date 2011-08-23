package org.bouncycastle.asn1.eac;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;

public abstract class PublicKeyDataObject
    extends ASN1Object
{
    public static PublicKeyDataObject getInstance(Object obj)
        throws IOException
    {
        if (obj instanceof PublicKeyDataObject)
        {
            return (PublicKeyDataObject)obj;
        }
        if (obj != null)
        {
            return new RSAPublicKey(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public abstract ASN1ObjectIdentifier getUsage();
}
