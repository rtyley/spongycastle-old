package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

interface TlsClient
{
    void init(TlsProtocolHandler handler);

    int[] getCipherSuites();

    short[] getCompressionMethods();

    // Hashtable is (Integer -> byte[])
    Hashtable generateClientExtensions();

    void notifySessionID(byte[] sessionID);

    void notifySelectedCipherSuite(int selectedCipherSuite);

    void notifySelectedCompressionMethod(short selectedCompressionMethod);

    void notifySecureRenegotiation(boolean secureNegotiation) throws IOException;

    // Hashtable is (Integer -> byte[])
    void processServerExtensions(Hashtable serverExtensions);

    TlsKeyExchange createKeyExchange() throws IOException;

    // Vector is (X509Name)
    void processServerCertificateRequest(short[] certificateTypes, Vector certificateAuthorities);

    Certificate getCertificate();

    byte[] generateCertificateSignature(byte[] md5andsha1) throws IOException;

    TlsCipher createCipher(SecurityParameters securityParameters) throws IOException;
}
