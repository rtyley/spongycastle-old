package org.bouncycastle.crypto.tls;

import java.util.Hashtable;

interface TlsClient
{
    CertificateVerifyer getCertificateVerifyer();

    byte[] generateCertificateSignature(byte[] md5andsha1);

    Certificate getCertificate();

    // Hashtable is (Integer -> byte[])
    Hashtable generateClientExtensions();

    // Hashtable is (Integer -> byte[])
    void processServerExtensions(Hashtable serverExtensions);
}
