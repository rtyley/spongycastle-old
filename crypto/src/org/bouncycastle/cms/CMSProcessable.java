package org.bouncycastle.cms;

import java.io.IOException;
import java.io.OutputStream;

public interface CMSProcessable
{
    /**
     * generic routine to copy out the data we want processed - the OutputStream
     * passed in will do the handling on it's own.
     * <p>
     * Note: this routine may be called multiple times.
     */
    public void write(OutputStream out)
        throws IOException, CMSException;

    public Object getContent();
}
