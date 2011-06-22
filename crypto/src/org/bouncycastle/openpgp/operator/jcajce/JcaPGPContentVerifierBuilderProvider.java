package org.bouncycastle.openpgp.operator.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.jcajce.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.NamedJcaJceHelper;
import org.bouncycastle.jcajce.ProviderJcaJceHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.PGPContentVerifier;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilder;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;

public class JcaPGPContentVerifierBuilderProvider
    implements PGPContentVerifierBuilderProvider
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private JcaPGPKeyConverter keyConverter = new JcaPGPKeyConverter();

    public JcaPGPContentVerifierBuilderProvider()
    {
    }

    public JcaPGPContentVerifierBuilderProvider setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));
        keyConverter.setProvider(provider);

        return this;
    }

    public JcaPGPContentVerifierBuilderProvider setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));
        keyConverter.setProvider(providerName);

        return this;
    }

    public PGPContentVerifierBuilder get(int keyAlgorithm, int hashAlgorithm)
        throws PGPException
    {
        return new JcaPGPContentVerifierBuilder(keyAlgorithm, hashAlgorithm);
    }

    private class JcaPGPContentVerifierBuilder
        implements PGPContentVerifierBuilder
    {
        private int hashAlgorithm;
        private int keyAlgorithm;

        public JcaPGPContentVerifierBuilder(int keyAlgorithm, int hashAlgorithm)
        {
            this.keyAlgorithm = keyAlgorithm;
            this.hashAlgorithm = hashAlgorithm;
        }

        public PGPContentVerifier build(final PGPPublicKey publicKey)
            throws PGPException
        {
            final Signature signature = helper.createSignature(keyAlgorithm, hashAlgorithm);

            try
            {
                signature.initVerify(keyConverter.getPublicKey(publicKey));
            }
            catch (InvalidKeyException e)
            {
                throw new PGPException("invalid key.", e);
            }

            return new PGPContentVerifier()
            {
                public int getHashAlgorithm()
                {
                    return hashAlgorithm;
                }

                public int getKeyAlgorithm()
                {
                    return keyAlgorithm;
                }

                public long getKeyID()
                {
                    return publicKey.getKeyID();
                }

                public boolean verify(byte[] expected)
                {
                    try
                    {
                        return signature.verify(expected);
                    }
                    catch (SignatureException e)
                    {   // TODO: need a specific runtime exception for PGP operators.
                        throw new IllegalStateException("unable to verify signature");
                    }
                }

                public OutputStream getOutputStream()
                {
                    return new SignatureOutputStream(signature);
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
                    throw new IOException("signature update caused exception: " + e.getMessage());
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
                    throw new IOException("signature update caused exception: " + e.getMessage());
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
                    throw new IOException("signature update caused exception: " + e.getMessage());
                }
            }
        }
    }
}
