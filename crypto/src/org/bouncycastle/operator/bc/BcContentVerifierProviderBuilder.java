package org.bouncycastle.operator.bc;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Date;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DatedContentVerifier;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.RawContentVerifier;

public class BcContentVerifierProviderBuilder
{
    private DigestAlgorithmIdentifierFinder digestAlgorithmFinder;

    public BcContentVerifierProviderBuilder()
    {
        digestAlgorithmFinder = new DefaultDigestAlgorithmIdentifierFinder();
    }

    public ContentVerifierProvider build(final X509CertificateHolder certHolder)
        throws OperatorCreationException
    {
        return new ContentVerifierProvider()
        {
            private BcSignerOutputStream stream;

            public ContentVerifier get(AlgorithmIdentifier algorithm)
                throws OperatorCreationException
            {
                try
                {
                    Signer sig = createSignature(algorithm);

                    AsymmetricKeyParameter publicKey = PublicKeyFactory.createKey(certHolder.getSubjectPublicKeyInfo());

                    sig.init(false, publicKey);

                    stream = new BcSignerOutputStream(sig);

                    Signer rawSig = createRawSig(algorithm, publicKey);

                    if (rawSig != null)
                    {
                        return new DatedRawSigVerifier(stream, certHolder, rawSig);
                    }
                    else
                    {
                        return new DatedSigVerifier(stream, certHolder);
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
        Signer sig = createSignature(algorithm);

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

    private Signer createSignature(AlgorithmIdentifier sigAlgId)
        throws OperatorCreationException
    {
        AlgorithmIdentifier digAlg = digestAlgorithmFinder.find(sigAlgId);
        Digest dig = BcUtil.createDigest(digAlg);

        return new RSADigestSigner(dig);
    }

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

    private class DatedSigVerifier
        extends SigVerifier
        implements DatedContentVerifier
    {
        private X509CertificateHolder certificate;

        DatedSigVerifier(BcSignerOutputStream stream, X509CertificateHolder certificate)
        {
            super(stream);
            this.certificate = certificate;
        }

        public Date getNotBefore()
        {
            return certificate.toASN1Structure().getStartDate().getDate();
        }

        public Date getNotAfter()
        {
            return certificate.toASN1Structure().getEndDate().getDate();
        }

        public boolean isValid(Date date)
        {
            return !date.before(getNotBefore()) && !date.after(getNotAfter());
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

    private class DatedRawSigVerifier
        extends RawSigVerifier
        implements DatedContentVerifier
    {
        private X509CertificateHolder certificate;

        DatedRawSigVerifier(BcSignerOutputStream stream, X509CertificateHolder certificate, Signer rawSignature)
        {
            super(stream, rawSignature);
            this.certificate = certificate;
        }

        public Date getNotBefore()
        {
            return certificate.toASN1Structure().getStartDate().getDate();
        }

        public Date getNotAfter()
        {
            return certificate.toASN1Structure().getEndDate().getDate();
        }

        public boolean isValid(Date date)
        {
            return !date.before(getNotBefore()) && !date.after(getNotAfter());
        }
    }
}