package org.bouncycastle.cms;

import java.io.IOException;
import java.io.InputStream;
import java.security.Provider;

import javax.crypto.SecretKey;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

interface CMSSecureReadable
{
    AlgorithmIdentifier getAlgorithm();
    Object getCryptoObject();
    CMSReadable getReadable(SecretKey key, Provider provider)
        throws CMSException;
    InputStream getInputStream()
            throws IOException, CMSException;
}
