package org.bouncycastle.jcajce.provider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class ProviderUtil
{
    private static final long  MAX_MEMORY = Runtime.getRuntime().maxMemory();

    public static int getReadLimit(InputStream in)
        throws IOException
    {
        if (in instanceof ByteArrayInputStream)
        {
            return in.available();
        }

        if (MAX_MEMORY > Integer.MAX_VALUE)
        {
            return Integer.MAX_VALUE;
        }

        return (int)MAX_MEMORY;
    }


//
//    public static ECParameterSpec getEcImplicitlyCa()
//    {
//        return null;
//    }
}
