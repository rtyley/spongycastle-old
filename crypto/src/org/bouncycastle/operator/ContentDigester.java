package org.bouncycastle.operator;

import java.io.OutputStream;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface ContentDigester
{
    AlgorithmIdentifier getAlgorithmIdentifier();

    /**
     * Returns a stream that will accept data for the purpose of calculating
     * a digest. Use org.bouncycastle.util.io.TeeOutputStream if you want to accumulate
     * the data on the fly as well.
     *
     * @return an OutputStream
     */
    OutputStream getOutputStream();

    byte[] getDigest();
}
