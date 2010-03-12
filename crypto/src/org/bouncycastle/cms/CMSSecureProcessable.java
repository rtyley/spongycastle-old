package org.bouncycastle.cms;

import java.security.Provider;

import javax.crypto.SecretKey;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

interface CMSSecureProcessable
{
    AlgorithmIdentifier getAlgorithm();
    Object getCryptoObject();
    CMSProcessable getProcessable(SecretKey key, Provider provider)
        throws CMSException;
}
