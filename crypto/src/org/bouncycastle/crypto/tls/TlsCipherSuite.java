package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;

/**
 * A generic class for ciphersuites in TLS 1.0.
 */
abstract class TlsCipherSuite
{
    protected static final short KE_RSA = 1;
    protected static final short KE_RSA_EXPORT = 2;
    protected static final short KE_DHE_DSS = 3;
    protected static final short KE_DHE_DSS_EXPORT = 4;
    protected static final short KE_DHE_RSA = 5;
    protected static final short KE_DHE_RSA_EXPORT = 6;
    protected static final short KE_DH_DSS = 7;
    protected static final short KE_DH_RSA = 8;
    protected static final short KE_DH_anon = 9;
    protected static final short KE_SRP = 10;
    protected static final short KE_SRP_RSA = 11;
    protected static final short KE_SRP_DSS = 12;

    protected abstract void skipServerCertificate() throws IOException;
    protected abstract void processServerCertificate(Certificate serverCertificate) throws IOException;

    protected abstract void skipServerKeyExchange() throws IOException;
    protected abstract void processServerKeyExchange(InputStream is, SecurityParameters securityParameters)
        throws IOException;

    protected abstract byte[] generateClientKeyExchange() throws IOException;

    protected abstract byte[] getPremasterSecret();

    protected abstract TlsCipher createCipher(SecurityParameters securityParameters);
}
