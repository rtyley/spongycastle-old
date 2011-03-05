package org.spongycastle.cms;

import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.cms.SignerInfo;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

interface SignerIntInfoGenerator
{
    SignerInfo generate(DERObjectIdentifier contentType, AlgorithmIdentifier digestAlgorithm,
        byte[] calculatedDigest) throws CMSStreamException;
}
