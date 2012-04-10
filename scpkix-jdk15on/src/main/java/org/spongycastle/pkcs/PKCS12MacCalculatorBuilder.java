package org.spongycastle.pkcs;

import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.operator.MacCalculator;

public interface PKCS12MacCalculatorBuilder
{
    MacCalculator build(char[] password);

    AlgorithmIdentifier getDigestAlgorithmIdentifier();
}
