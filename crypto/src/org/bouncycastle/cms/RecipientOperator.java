package org.bouncycastle.cms;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.InputDecryptor;
import org.bouncycastle.operator.MacCalculator;

public class RecipientOperator
{
    private final AlgorithmIdentifier algorithmIdentifier;
    private final Object operator;

    public RecipientOperator(InputDecryptor decryptor)
    {
        this.algorithmIdentifier = decryptor.getAlgorithmIdentifier();
        this.operator = decryptor;
    }

    public RecipientOperator(MacCalculator macCalculator)
    {
        this.algorithmIdentifier = macCalculator.getAlgorithmIdentifier();
        this.operator = macCalculator;
    }

    public InputStream getInputStream(InputStream dataIn)
    {
        if (operator instanceof InputDecryptor)
        {
            return ((InputDecryptor)operator).getInputStream(dataIn);
        }
        else
        {
            return new WrappingStream(((MacCalculator)operator).getOutputStream(), dataIn);
        }
    }

    public boolean isMacBased()
    {
        return operator instanceof MacCalculator;
    }

    public byte[] getMac()
    {
        return ((MacCalculator)operator).getMac();
    }

    private class WrappingStream extends InputStream
    {
        private OutputStream output;
        private InputStream input;

        private WrappingStream(OutputStream output, InputStream input)
        {
            this.output = output;
            this.input = input;
        }

        public int read()
            throws IOException
        {
            int b = input.read();

            if (b < 0)
            {
                return b;
            }

            output.write(b);

            return b;
        }
    }
}
