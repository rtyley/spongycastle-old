package org.bouncycastle.util.io.pem;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.Iterator;
import java.util.Map;

import org.bouncycastle.util.encoders.Base64;

/**
 * A generic PEM writer, based on RFC 1421
 */
public class PemWriter
    extends BufferedWriter
{
    /**
     * Base constructor.
     *
     * @param out output stream to use.
     */
    public PemWriter(Writer out)
    {
        super(out);
    }

    public void writePemObject(PemObject obj)
        throws IOException
    {
        writePreEncapsulationBoundary(obj.getType());

        if (!obj.getHeaders().isEmpty())
        {
            Map headers = obj.getHeaders();

            for (Iterator it = obj.getHeaders().keySet().iterator(); it.hasNext();)
            {
                String hdr = (String)it.next();

                this.write(hdr);
                this.write(": ");
                this.write((String)headers.get(hdr));
                this.newLine();
            }

            this.newLine();
        }
        
        writeEncoded(obj.getContent());
        writePostEncapsulationBoundary(obj.getType());
    }

    private void writeEncoded(byte[] bytes)
        throws IOException
    {
        char[]  buf = new char[64];

        bytes = Base64.encode(bytes);

        for (int i = 0; i < bytes.length; i += buf.length)
        {
            int index = 0;

            while (index != buf.length)
            {
                if ((i + index) >= bytes.length)
                {
                    break;
                }
                buf[index] = (char)bytes[i + index];
                index++;
            }
            this.write(buf, 0, index);
            this.newLine();
        }
    }

    private void writePreEncapsulationBoundary(
        String type)
        throws IOException
    {
        this.write("-----BEGIN " + type + "-----");
        this.newLine();
    }

    private void writePostEncapsulationBoundary(
        String type)
        throws IOException
    {
        this.write("-----END " + type + "-----");
        this.newLine();
    }
}
