package org.bouncycastle.util.io.pem;

import java.util.Collections;
import java.util.Map;

public class PemObject
    implements PemObjectGenerator
{
    private String type;
    private Map    headers;
    private byte[] content;

    public PemObject(String type, byte[] content)
    {
        this(type, Collections.emptyMap(), content);
    }

    public PemObject(String type, Map headers, byte[] content)
    {
        this.type = type;
        this.headers = Collections.unmodifiableMap(headers);
        this.content = content;
    }

    public String getType()
    {
        return type;
    }

    public Map getHeaders()
    {
        return headers;
    }

    public byte[] getContent()
    {
        return content;
    }

    public PemObject generate()
        throws PemGenerationException
    {
        return this;
    }
}
