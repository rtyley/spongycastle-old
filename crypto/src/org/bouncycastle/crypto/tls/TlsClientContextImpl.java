package org.bouncycastle.crypto.tls;

import java.security.SecureRandom;

class TlsClientContextImpl implements TlsClientContext
{
    private SecureRandom secureRandom;

    TlsClientContextImpl(SecureRandom secureRandom)
    {
        this.secureRandom = secureRandom;
    }

    public SecureRandom getSecureRandom()
    {
        return secureRandom;
    }
}
