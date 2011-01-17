package org.bouncycastle.crypto.tls;

/**
 * This should be implemented by any class which can find out, if a given certificate
 * chain is being accepted by an client.
 * @deprecated use CertificateVerifier
 */
public interface CertificateVerifyer
    extends CertificateVerifier
{
}
