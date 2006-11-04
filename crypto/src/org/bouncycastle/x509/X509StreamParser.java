package org.bouncycastle.x509;

import org.bouncycastle.util.StreamParser;
import org.bouncycastle.util.StreamParsingException;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.util.Collection;

public class X509StreamParser
    implements StreamParser
{
    public static X509StreamParser getInstance(String type, InputStream stream)
        throws NoSuchParserException
    {
        try
        {
            X509Util.Implementation impl = X509Util.getImplementation("X509StreamParser", type);

            return createParser(impl, stream);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new NoSuchParserException(e.getMessage());
        }
    }

    public static X509StreamParser getInstance(String type, InputStream stream, String provider)
        throws NoSuchParserException, NoSuchProviderException
    {
        try
        {
            X509Util.Implementation impl = X509Util.getImplementation("X509StreamParser", type, provider);

            return createParser(impl, stream);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new NoSuchParserException(e.getMessage());
        }
    }

    public static X509StreamParser getInstance(String type, byte[] stream)
        throws NoSuchParserException
    {
        return getInstance(type, new ByteArrayInputStream(stream));
    }

    public static X509StreamParser getInstance(String type, byte[] stream, String provider)
        throws NoSuchParserException, NoSuchProviderException
    {
        return getInstance(type, new ByteArrayInputStream(stream), provider);
    }
    
    private static X509StreamParser createParser(X509Util.Implementation impl, InputStream stream)
    {
        X509StreamParserSpi spi = (X509StreamParserSpi)impl.getEngine();

        spi.engineInit(stream);

        return new X509StreamParser(impl.getProvider(), spi);
    }

    private Provider            _provider;
    private X509StreamParserSpi _spi;

    private X509StreamParser(
        Provider provider,
        X509StreamParserSpi spi)
    {
        _provider = provider;
        _spi = spi;
    }

    public Object read()
        throws StreamParsingException
    {
        return _spi.engineRead();
    }

    public Collection readAll()
        throws StreamParsingException
    {
        return _spi.engineReadAll();
    }
}
