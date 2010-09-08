package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.List;

interface TlsClient
{
    void init(TlsProtocolHandler handler);

    int[] getCipherSuites();

    // Hashtable is (Integer -> byte[])
    Hashtable generateClientExtensions();

    void notifySessionID(byte[] sessionID);

    void notifySelectedCipherSuite(int selectedCipherSuite);

    void notifySecureRenegotiation(boolean secureNegotiation) throws IOException;

    // Hashtable is (Integer -> byte[])
    void processServerExtensions(Hashtable serverExtensions);

    TlsKeyExchange createKeyExchange() throws IOException;

    // List is (X509Name)
    void processServerCertificateRequest(byte[] certificateTypes, List certificateAuthorities);

    byte[] generateCertificateSignature(byte[] md5andsha1) throws IOException;

    Certificate getCertificate();

    TlsCipher createCipher(SecurityParameters securityParameters) throws IOException;
}
