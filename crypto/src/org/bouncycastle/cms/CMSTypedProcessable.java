package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface CMSTypedProcessable
    extends CMSProcessable
{
    ASN1ObjectIdentifier getContentType();
}
