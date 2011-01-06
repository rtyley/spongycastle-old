package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * A generic interface for key exchange implementations in TLS 1.0.
 */
interface TlsKeyExchange
{
    void skipServerCertificate() throws IOException;

    void processServerCertificate(Certificate serverCertificate) throws IOException;

    void skipServerKeyExchange() throws IOException;

    void processServerKeyExchange(InputStream is)
        throws IOException;

    void generateClientKeyExchange(OutputStream os) throws IOException;

    byte[] generatePremasterSecret() throws IOException;
}
