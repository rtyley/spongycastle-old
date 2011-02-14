package org.bouncycastle.cms.jcajce;

import java.io.IOException;
import java.io.InputStream;
import java.util.zip.InflaterInputStream;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.InputExpander;
import org.bouncycastle.operator.InputExpanderProvider;
import org.bouncycastle.util.io.StreamOverflowException;

public class ZlibExpanderProvider
    implements InputExpanderProvider
{
    private final long limit;

    public ZlibExpanderProvider()
    {
        this.limit = 0;
    }

    /**
     * Create a provider which caps the number of expanded bytes that can be produced when the
     * compressed stream is parsed.
     *
     * @param limit max number of bytes allowed in an expanded stream.
     */
    public ZlibExpanderProvider(long limit)
    {
        this.limit = limit;
    }

    public InputExpander get(final AlgorithmIdentifier algorithm)
    {
        return new InputExpander()
        {

            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return algorithm;
            }

            public InputStream getInputStream(InputStream comIn)
            {
                if (limit == 0)
                {
                    return new InflaterInputStream(comIn);
                }
                else
                {
                    return new LimitedInflaterInputStream(comIn);
                }
            }
        };
    }

    private class LimitedInflaterInputStream
        extends InputStream
    {
        private InputStream comIn;
        private long maxLeft;

        public LimitedInflaterInputStream(InputStream comIn)
        {
            this.comIn = new InflaterInputStream(comIn);
            this.maxLeft = limit;
        }

        public int read(byte[] inBuf)
            throws IOException
        {
            return read(inBuf, 0, inBuf.length);
        }

        public int read(byte[] inBuf, int inOff, int inLen)
            throws IOException
        {
            if (maxLeft >= inLen)
            {
                maxLeft -= inLen;
                return comIn.read(inBuf, inOff, inLen);
            }
            else
            {
                int b;
                int count = 0;

                while ((b = this.read()) >= 0 && inLen != count)
                {
                    inBuf[inOff++] = (byte)b;
                    count++;
                }

                if (count == 0 && inLen != 0)
                {
                    return -1;
                }
                
                return count;
            }
        }

        public int read()
            throws IOException
        {
            int b = comIn.read();

            if (b < 0)
            {
                return b;
            }

            if (--maxLeft < 0)
            {
                throw new StreamOverflowException("expanded byte limit exceeded");
            }
            return b;
        }
    }
}
