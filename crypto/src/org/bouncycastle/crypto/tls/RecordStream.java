package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.crypto.Signer;

/**
 * An implementation of the TLS 1.0 record layer.
 */
class RecordStream
{
    private TlsProtocolHandler handler;
    private InputStream is;
    private OutputStream os;
    protected CombinedHash hash1;
    protected CombinedHash hash2;
    protected TlsCipherSuite readSuite = null;
    protected TlsCipherSuite writeSuite = null;

    Signer clientSigner = null;

    RecordStream(TlsProtocolHandler handler, InputStream is, OutputStream os)
    {
        this.handler = handler;
        this.is = is;
        this.os = os;
        this.hash1 = new CombinedHash();
        this.hash2 = new CombinedHash();
        this.readSuite = new TlsNullCipherSuite();
        this.writeSuite = this.readSuite;
    }

    public void readData() throws IOException
    {
        short type = TlsUtils.readUint8(is);
        TlsUtils.checkVersion(is, handler);
        int size = TlsUtils.readUint16(is);
        byte[] buf = decodeAndVerify(type, is, size);
        handler.processData(type, buf, 0, buf.length);
    }

    protected byte[] decodeAndVerify(short type, InputStream is, int len) throws IOException
    {
        byte[] buf = new byte[len];
        TlsUtils.readFully(buf, is);
        byte[] result = readSuite.decodeCiphertext(type, buf, 0, buf.length);
        return result;
    }

    protected void writeMessage(short type, byte[] message, int offset, int len) throws IOException
    {
        if (type == 22) // TlsProtocolHandler.RL_HANDSHAKE
        {
            updateHandshakeData(message, offset, len);
        }
        byte[] ciphertext = writeSuite.encodePlaintext(type, message, offset, len);
        byte[] writeMessage = new byte[ciphertext.length + 5];
        TlsUtils.writeUint8(type, writeMessage, 0);
        TlsUtils.writeUint8((short)3, writeMessage, 1);
        TlsUtils.writeUint8((short)1, writeMessage, 2);
        TlsUtils.writeUint16(ciphertext.length, writeMessage, 3);
        System.arraycopy(ciphertext, 0, writeMessage, 5, ciphertext.length);
        os.write(writeMessage);
        os.flush();
    }

    void updateHandshakeData(byte[] message, int offset, int len)
    {
        hash1.update(message, offset, len);
        hash2.update(message, offset, len);

        if (clientSigner != null)
        {
            clientSigner.update(message, offset, len);
        }
    }

    protected void close() throws IOException
    {
        IOException e = null;
        try
        {
            is.close();
        }
        catch (IOException ex)
        {
            e = ex;
        }
        try
        {
            os.close();
        }
        catch (IOException ex)
        {
            e = ex;
        }
        if (e != null)
        {
            throw e;
        }
    }

    protected void flush() throws IOException
    {
        os.flush();
    }
}
