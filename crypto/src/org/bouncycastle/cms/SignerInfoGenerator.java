package org.bouncycastle.cms;

import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;

interface SignerInfoGenerator
{
    /**
     * Return the stream that will either calculate a digest
     * attribute or the signature stored in the signer info.
     */
    OutputStream getCalculatingOutputStream();

    SignerInfo generate(ASN1ObjectIdentifier contentType)
        throws CMSStreamException;
}
