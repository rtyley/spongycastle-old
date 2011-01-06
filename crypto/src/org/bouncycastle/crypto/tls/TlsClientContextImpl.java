package org.bouncycastle.crypto.tls;

import java.security.SecureRandom;

class TlsClientContextImpl implements TlsClientContext
{
    private SecureRandom secureRandom;

    private Object userObject = null;

    TlsClientContextImpl(SecureRandom secureRandom)
    {
        this.secureRandom = secureRandom;
    }

    public SecureRandom getSecureRandom()
    {
        return secureRandom;
    }

    public Object getUserObject()
    {
        return userObject;
    }

    public void setUserObject(Object userObject)
    {
        this.userObject = userObject;
    }
}
