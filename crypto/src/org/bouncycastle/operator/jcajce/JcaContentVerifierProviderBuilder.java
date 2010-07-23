package org.bouncycastle.operator.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OperatorStreamException;
import org.bouncycastle.operator.RuntimeOperatorException;

public class JcaContentVerifierProviderBuilder
{
    private OperatorHelper helper = new DefaultOperatorHelper();

    public JcaContentVerifierProviderBuilder()
    {
    }

    public JcaContentVerifierProviderBuilder setProvider(Provider provider)
    {
        this.helper = new ProviderOperatorHelper(provider);

        return this;
    }

    public JcaContentVerifierProviderBuilder setProvider(String providerName)
    {
        this.helper = new NamedOperatorHelper(providerName);

        return this;
    }

    public ContentVerifierProvider build(final PublicKey publicKey)
        throws OperatorCreationException
    {
        return new ContentVerifierProvider()
        {
            private SignatureOutputStream stream;

            public ContentVerifier get(AlgorithmIdentifier algorithm)
                throws OperatorCreationException
            {
                try
                {
                    Signature sig = helper.createSignature(algorithm);

                    sig.initVerify(publicKey);

                    stream = new SignatureOutputStream(sig);
                }
                catch (GeneralSecurityException e)
                {
                    throw new OperatorCreationException("exception on setup: " + e, e);
                }

                return new ContentVerifier()
                {
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
                        try
                        {
                            return stream.verify(expected);
                        }
                        catch (SignatureException e)
                        {
                            throw new RuntimeOperatorException("exception obtaining signature: " + e.getMessage(), e);
                        }
                    }
                };
            }
        };
    }

    private class SignatureOutputStream
        extends OutputStream
    {
        private Signature sig;

        SignatureOutputStream(Signature sig)
        {
            this.sig = sig;
        }

        public void write(byte[] bytes, int off, int len)
            throws IOException
        {
            try
            {
                sig.update(bytes, off, len);
            }
            catch (SignatureException e)
            {
                throw new OperatorStreamException("exception in content signer: " + e.getMessage(), e);
            }
        }

        public void write(byte[] bytes)
            throws IOException
        {
            try
            {
                sig.update(bytes);
            }
            catch (SignatureException e)
            {
                throw new OperatorStreamException("exception in content signer: " + e.getMessage(), e);
            }
        }

        public void write(int b)
            throws IOException
        {
            try
            {
                sig.update((byte)b);
            }
            catch (SignatureException e)
            {
                throw new OperatorStreamException("exception in content signer: " + e.getMessage(), e);
            }
        }

        boolean verify(byte[] expected)
            throws SignatureException
        {
            return sig.verify(expected);
        }
    }
}