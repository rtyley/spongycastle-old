package org.bouncycastle.cms;

import java.io.IOException;
import java.io.OutputStream;

import javax.crypto.Mac;

class MacOutputStream extends OutputStream
{
    // FIXME Need internal access in RecipientInformation atm
    final Mac mac;

    MacOutputStream(Mac mac)
    {
        this.mac = mac;
    }

    public void write(byte[] b, int off, int len) throws IOException
    {
        mac.update(b, off, len);
    }

    public void write(int b) throws IOException
    {
        mac.update((byte) b);
    }
}
