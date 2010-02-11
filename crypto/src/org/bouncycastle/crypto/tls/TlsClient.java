package org.bouncycastle.crypto.tls;

interface TlsClient
{
    CertificateVerifyer getCertificateVerifyer();
    byte[] generateCertificateSignature(byte[] md5andsha1);
    Certificate getCertificate();
}
