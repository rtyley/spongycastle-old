package org.bouncycastle.operator;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class SignerProperties
{
    private final AlgorithmIdentifier sigAlgId;
    private final AlgorithmIdentifier encAlgId;
    private final AlgorithmIdentifier digAlgId;

    public SignerProperties(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier encAlgId, AlgorithmIdentifier digAlgId)
    {
        this.sigAlgId = sigAlgId;
        this.encAlgId = encAlgId;
        this.digAlgId = digAlgId;
    }

    public AlgorithmIdentifier getDigestAlgorithmIdentifier()
    {
        return digAlgId;
    }

    public AlgorithmIdentifier getEncryptionAlgorithmIdentifier()
    {
        return encAlgId;
    }

    public AlgorithmIdentifier getSignatureAlgorithmIdentifier()
    {
        return sigAlgId;
    }
}
