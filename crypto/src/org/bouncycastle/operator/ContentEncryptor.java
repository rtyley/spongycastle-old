package org.bouncycastle.operator;

import java.io.OutputStream;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface ContentEncryptor
{
    AlgorithmIdentifier getAlgorithmIdentifier();

    OutputStream getEncryptingOutputStream(OutputStream dataOut);

    byte[] getEncodedKey();
}
