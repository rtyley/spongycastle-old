package org.bouncycastle.operator;

import java.io.OutputStream;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface ContentVerifier
{
    void setup(AlgorithmIdentifier algorithmIdentifier)
        throws OperatorCreationException;

    /**
     * Returns a stream that will accept data for the purpose of calculating
     * a signature for later verification. Use org.bouncycastle.util.io.TeeOutputStream if you want to accumulate
     * the data on the fly as well.
     *
     * @return an OutputStream
     */
    OutputStream getVerifierOutputStream();

    /**
     * @param expected expected value of the signature on the data.
     * @return true if the signature verifies, false otherwise
     */
    boolean verify(byte[] expected);
}