package org.bouncycastle.operator.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Provider;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.NamedJcaJceHelper;
import org.bouncycastle.jcajce.ProviderJcaJceHelper;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigesterCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;

public class JcaContentDigesterProviderBuilder
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());

    public JcaContentDigesterProviderBuilder()
    {
    }

    public JcaContentDigesterProviderBuilder setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

        return this;
    }

    public JcaContentDigesterProviderBuilder setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

        return this;
    }

    public DigesterCalculatorProvider build()
        throws OperatorCreationException
    {
        return new DigesterCalculatorProvider()
        {
            private DigestOutputStream stream;

            public DigestCalculator get(final AlgorithmIdentifier algorithm)
                throws OperatorCreationException
            {
                try
                {
                    MessageDigest dig = helper.createDigest(algorithm);

                    stream = new DigestOutputStream(dig);
                }
                catch (GeneralSecurityException e)
                {
                    throw new OperatorCreationException("exception on setup: " + e, e);
                }

                return new DigestCalculator()
                {
                    public AlgorithmIdentifier getAlgorithmIdentifier()
                    {
                        return algorithm;
                    }
                    
                    public OutputStream getOutputStream()
                    {
                        return stream;
                    }

                    public byte[] getDigest()
                    {
                        return stream.getDigest();
                    }
                };
            }
        };
    }

    private class DigestOutputStream
        extends OutputStream
    {
        private MessageDigest dig;

        DigestOutputStream(MessageDigest dig)
        {
            this.dig = dig;
        }

        public void write(byte[] bytes, int off, int len)
            throws IOException
        {
            dig.update(bytes, off, len);
        }

        public void write(byte[] bytes)
            throws IOException
        {
           dig.update(bytes);
        }

        public void write(int b)
            throws IOException
        {
           dig.update((byte)b);
        }

        byte[] getDigest()
        {
            return dig.digest();
        }
    }
}