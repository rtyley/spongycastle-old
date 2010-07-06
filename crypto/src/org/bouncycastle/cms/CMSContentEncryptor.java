package org.bouncycastle.cms;

import java.io.OutputStream;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface CMSContentEncryptor
{
    AlgorithmIdentifier getAlgorithmIdentifier();

    OutputStream getEncryptingOutputStream(OutputStream dataOut)
        throws CMSException;

    byte[] getEncodedKey();
}
