package org.bouncycastle.operator.bc;

import java.io.OutputStream;
import java.security.SecureRandom;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.bouncycastle.operator.SignerAlgorithmIdentifierGenerator;

public abstract class BcContentSignerBuilder
{
    private SecureRandom random;
    private String signatureAlgorithm;
    private AlgorithmIdentifier sigAlgId;
    private DigestAlgorithmIdentifierFinder digestAlgorithmFinder;

    public BcContentSignerBuilder(String signatureAlgorithm)
    {
        this.signatureAlgorithm = signatureAlgorithm;
        this.sigAlgId = SignerAlgorithmIdentifierGenerator.generate(signatureAlgorithm);
        this.digestAlgorithmFinder = new DefaultDigestAlgorithmIdentifierFinder();
    }

    public BcContentSignerBuilder setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public ContentSigner build(AsymmetricKeyParameter privateKey)
        throws OperatorCreationException
    {
        final Signer sig = createSignature(sigAlgId, digestAlgorithmFinder.find(sigAlgId));

        if (random != null)
        {
            sig.init(true, new ParametersWithRandom(privateKey, random));
        }
        else
        {
            sig.init(true, privateKey);
        }

        return new ContentSigner()
        {
            private BcSignerOutputStream stream = new BcSignerOutputStream(sig);

            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return sigAlgId;
            }

            public OutputStream getOutputStream()
            {
                return stream;
            }

            public byte[] getSignature()
            {
                try
                {
                    return stream.getSignature();
                }
                catch (CryptoException e)
                {
                    throw new RuntimeOperatorException("exception obtaining signature: " + e.getMessage(), e);
                }
            }
        };
    }

    protected abstract Signer createSignature(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier algorithmIdentifier)
        throws OperatorCreationException;
}
