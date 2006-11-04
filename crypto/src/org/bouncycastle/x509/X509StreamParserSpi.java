package org.bouncycastle.x509;

import org.bouncycastle.util.StreamParsingException;

import java.io.InputStream;
import java.util.Collection;

public abstract class X509StreamParserSpi
{
    public abstract void engineInit(InputStream in);

    public abstract Object engineRead() throws StreamParsingException;

    public abstract Collection engineReadAll() throws StreamParsingException;
}
