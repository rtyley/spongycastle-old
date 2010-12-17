package org.bouncycastle.operator.bc;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.RawContentVerifier;

public abstract class BcContentVerifierProviderBuilder
{
    public BcContentVerifierProviderBuilder()
    {
    }

    public ContentVerifierProvider build(final X509CertificateHolder certHolder)
        throws OperatorCreationException
    {
        return new ContentVerifierProvider()
        {
            private BcSignerOutputStream stream;

            public boolean hasAssociatedCertificate()
            {
                return true;
            }

            public X509CertificateHolder getAssociatedCertificate()
            {
                return certHolder;
            }

            public ContentVerifier get(AlgorithmIdentifier algorithm)
                throws OperatorCreationException
            {
                try
                {
                    Signer sig = createSigner(algorithm);

                    AsymmetricKeyParameter publicKey = PublicKeyFactory.createKey(certHolder.getSubjectPublicKeyInfo());

                    sig.init(false, publicKey);

                    stream = new BcSignerOutputStream(sig);

                    Signer rawSig = createRawSig(algorithm, publicKey);

                    if (rawSig != null)
                    {
                        return new RawSigVerifier(stream, rawSig);
                    }
                    else
                    {
                        return new SigVerifier(stream);
                    }

                }
                catch (IOException e)
                {
                    throw new OperatorCreationException("exception on setup: " + e, e);
                }
            }
        };
    }

    public ContentVerifierProvider build(final AsymmetricKeyParameter publicKey)
        throws OperatorCreationException
    {
        return new ContentVerifierProvider()
        {
            public boolean hasAssociatedCertificate()
            {
                return false;
            }

            public X509CertificateHolder getAssociatedCertificate()
            {
                return null;
            }

            public ContentVerifier get(AlgorithmIdentifier algorithm)
                throws OperatorCreationException
            {
                BcSignerOutputStream stream = createSignatureStream(algorithm, publicKey);

                Signer rawSig = createRawSig(algorithm, publicKey);

                if (rawSig != null)
                {
                    return new RawSigVerifier(stream, rawSig);
                }
                else
                {
                    return new SigVerifier(stream);
                }
            }
        };
    }

    private BcSignerOutputStream createSignatureStream(AlgorithmIdentifier algorithm, AsymmetricKeyParameter publicKey)
        throws OperatorCreationException
    {
        Signer sig = createSigner(algorithm);

        sig.init(false, publicKey);

        return new BcSignerOutputStream(sig);
    }

    private Signer createRawSig(AlgorithmIdentifier algorithm, AsymmetricKeyParameter publicKey)
    {
        Signer rawSig;
        try
        {
            rawSig = null;

            rawSig.init(false, publicKey);
        }
        catch (Exception e)
        {
            rawSig = null;
        }
        return rawSig;
    }

    protected abstract Signer createSigner(AlgorithmIdentifier sigAlgId)
        throws OperatorCreationException;

    private class SigVerifier
        implements ContentVerifier
    {
        private BcSignerOutputStream stream;

        SigVerifier(BcSignerOutputStream stream)
        {
            this.stream = stream;
        }

        public OutputStream getOutputStream()
        {
            if (stream == null)
            {
                throw new IllegalStateException("verifier not initialised");
            }

            return stream;
        }

        public boolean verify(byte[] expected)
        {
            return stream.verify(expected);
        }
    }

    private class RawSigVerifier
        extends SigVerifier
        implements RawContentVerifier
    {
        private Signer rawSignature;

        RawSigVerifier(BcSignerOutputStream stream, Signer rawSignature)
        {
            super(stream);
            this.rawSignature = rawSignature;
        }

        public boolean verify(byte[] digest, byte[] expected)
        {
            rawSignature.update(digest, 0, digest.length);

            return rawSignature.verifySignature(expected);
        }
    }
}