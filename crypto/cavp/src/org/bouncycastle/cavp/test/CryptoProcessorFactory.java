package org.spongycastle.cavp.test;

import org.spongycastle.cavp.test.CryptoProcessor;

public interface CryptoProcessorFactory
    {
        CryptoProcessor getDecryptor();

        CryptoProcessor getEncryptor();
    }
