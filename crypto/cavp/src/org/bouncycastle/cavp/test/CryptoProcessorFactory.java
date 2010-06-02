package org.bouncycastle.cavp.test;

import org.bouncycastle.cavp.test.CryptoProcessor;

public interface CryptoProcessorFactory
    {
        CryptoProcessor getDecryptor();

        CryptoProcessor getEncryptor();
    }
