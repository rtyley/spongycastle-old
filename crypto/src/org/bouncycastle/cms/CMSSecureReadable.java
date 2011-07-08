package org.bouncycastle.cms;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

interface CMSSecureReadable
{
    AlgorithmIdentifier getAlgorithm();
    Object getCryptoObject();

    InputStream getInputStream()
            throws IOException, CMSException;
}
