package org.bouncycastle.crypto.tls;

import java.security.SecureRandom;

public interface TlsClientContext
{
    SecureRandom getSecureRandom();

    Object getUserObject();

    void setUserObject(Object userObject);
}
