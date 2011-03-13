
package java.security;

import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public class AlgorithmParameters extends Object
{
    private AlgorithmParametersSpi spi;
    private Provider provider;
    private String algorithm;

    protected AlgorithmParameters(
        AlgorithmParametersSpi paramSpi,
        Provider provider,
        String algorithm)
    {
        this.spi = paramSpi;
        this.provider = provider;
        this.algorithm = algorithm;
    }

    public final String getAlgorithm()
    {
        return algorithm;
    }

    public final byte[] getEncoded() throws IOException
    {
        return spi.engineGetEncoded();
    }

    public final byte[] getEncoded(String format) throws IOException
    {
        return spi.engineGetEncoded(format);
    }

    public static AlgorithmParameters getInstance(String algorithm)
    throws NoSuchAlgorithmException
    {
        return null;
    }

    public static AlgorithmParameters getInstance(
        String algorithm,
        String provider)
    throws NoSuchAlgorithmException, NoSuchProviderException
    {
        return null;
    }

    public final AlgorithmParameterSpec getParameterSpec(Class paramSpec)
    throws InvalidParameterSpecException
    {
        return spi.engineGetParameterSpec(paramSpec);
    }

    public final Provider getProvider()
    {
        return provider;
    }

    public final void init(AlgorithmParameterSpec paramSpec)
    throws InvalidParameterSpecException
    {
        spi.engineInit(paramSpec);
    }

    public final void init(byte[] params) throws IOException
    {
        spi.engineInit(params);
    }

    public final void init(byte[] params, String format) throws IOException
    {
        spi.engineInit(params, format);
    }

    public final String toString()
    {
        return spi.engineToString();
    }
}
