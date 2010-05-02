package org.bouncycastle.cms;

import java.io.IOException;
import java.io.InputStream;

interface CMSReadable
{
    public InputStream read()
        throws IOException, CMSException;
}
