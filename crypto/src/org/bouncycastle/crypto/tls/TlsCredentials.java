package org.bouncycastle.crypto.tls;

import java.io.IOException;

public interface TlsCredentials
{
    Certificate getCertificate();

    byte[] generateCertificateSignature(byte[] md5andsha1) throws IOException;
}
