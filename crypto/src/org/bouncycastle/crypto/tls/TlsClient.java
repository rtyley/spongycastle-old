package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.List;

interface TlsClient
{
    TlsCipherSuite createCipherSuite(int cipherSuite) throws IOException;

    int[] getCipherSuites();

    byte[] generateCertificateSignature(byte[] md5andsha1) throws IOException;

    Certificate getCertificate();

    // Hashtable is (Integer -> byte[])
    Hashtable generateClientExtensions();

    // Hashtable is (Integer -> byte[])
    void processServerExtensions(Hashtable serverExtensions);

    // List is (X509Name)
    void processServerCertificateRequest(byte[] certificateTypes, List certificateAuthorities);
}
