package org.bouncycastle.operator;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;

public interface ContentVerifierProvider
{
    boolean hasAssociatedCertificate();

    X509CertificateHolder getAssociatedCertificate();

    ContentVerifier get(AlgorithmIdentifier verifierAlgorithmIdentifier)
        throws OperatorCreationException;
}
