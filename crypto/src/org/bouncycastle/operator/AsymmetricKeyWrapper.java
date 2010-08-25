package org.bouncycastle.operator;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

public abstract class AsymmetricKeyWrapper
    implements KeyWrapper
{
    private SubjectPublicKeyInfo keyInfo;

    protected AsymmetricKeyWrapper(SubjectPublicKeyInfo keyInfo)
    {
        this.keyInfo = keyInfo;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return keyInfo.getAlgorithmId();
    }
}
