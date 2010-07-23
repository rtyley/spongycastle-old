package org.bouncycastle.operator;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface ContentDigesterProvider
{
    ContentDigester get(AlgorithmIdentifier digestAlgorithmIdentifier)
        throws OperatorCreationException;
}
