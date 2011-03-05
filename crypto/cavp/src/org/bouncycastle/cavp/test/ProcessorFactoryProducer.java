package org.spongycastle.cavp.test;

import java.security.GeneralSecurityException;

public interface ProcessorFactoryProducer
{
    CryptoProcessorFactory createCryptoProcessorFactory(String algorithm)
        throws GeneralSecurityException;

    DigestProcessorFactory createDigestProcessorFactory(String digest)
        throws GeneralSecurityException;
}
