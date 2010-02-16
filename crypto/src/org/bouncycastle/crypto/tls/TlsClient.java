package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.List;

interface TlsClient
{
    void init(TlsProtocolHandler handler);

    TlsCipherSuite createCipherSuite(int cipherSuite) throws IOException;

    int[] getCipherSuites();

    byte[] generateCertificateSignature(byte[] md5andsha1) throws IOException;

    Certificate getCertificate();

    // Hashtable is (Integer -> byte[])
    Hashtable generateClientExtensions();

    void notifySessionID(byte[] sessionID);

    // Hashtable is (Integer -> byte[])
    void processServerExtensions(Hashtable serverExtensions);

    // List is (X509Name)
    void processServerCertificateRequest(byte[] certificateTypes, List certificateAuthorities);
}
