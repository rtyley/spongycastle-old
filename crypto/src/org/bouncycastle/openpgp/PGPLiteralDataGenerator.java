package org.bouncycastle.openpgp;

import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.PacketTags;

import java.io.File;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Date;

/**
 * Class for producing literal data packets.
 */
public class PGPLiteralDataGenerator 
{    
    public static final char    BINARY = PGPLiteralData.BINARY;
    public static final char    TEXT = PGPLiteralData.TEXT;
    
    /**
     * The special name indicating a "for your eyes only" packet.
     */
    public static final String  CONSOLE = PGPLiteralData.CONSOLE;
    
    /**
     * The special time for a modification time of "now" or
     * the present time.
     */
    public static final Date    NOW = PGPLiteralData.NOW;
    
    private BCPGOutputStream    pkOut;
    private boolean             oldFormat = false;
    
    public PGPLiteralDataGenerator()
    {        
    }
    
    /**
     * Generates literal data objects in the old format, this is
     * important if you need compatability with  PGP 2.6.x.
     * 
     * @param oldFormat
     */
    public PGPLiteralDataGenerator(
        boolean    oldFormat)
    {
        this.oldFormat = oldFormat;
    }
    
    private void writeHeader(
        OutputStream    out,
        char            format,
        String          name,
        long            modificationTime) 
        throws IOException
    {
        out.write(format);
        out.write((byte)name.length());

        for (int i = 0; i != name.length(); i++)
        {
            out.write(name.charAt(i));
        }

        long    modDate = modificationTime / 1000;

        out.write((byte)(modDate >> 24));
        out.write((byte)(modDate >> 16));
        out.write((byte)(modDate >> 8));
        out.write((byte)(modDate));
    }
    
    /**
     * Open a literal data packet, returning a stream to store the data inside
     * the packet. The stream can be closed off by either calling close()
     * on the stream or close() on the generator.
     * 
     * @param out the stream we want the packet in
     * @param format the format we are using
     * @param name the name of the "file"
     * @param length the length of the data we will write
     * @param modificationTime the time of last modification we want stored.
     */
    public OutputStream open(
        OutputStream    out,
        char            format,
        String          name,
        long            length,
        Date            modificationTime)
        throws IOException
    {
        if (pkOut != null)
        {
            throw new IllegalStateException("generator already in open state");
        }

        pkOut = new BCPGOutputStream(out, PacketTags.LITERAL_DATA, length + 2 + name.length() + 4, oldFormat);
        
        writeHeader(pkOut, format, name, modificationTime.getTime());

        return new LiteralDataWrappedStream(this, pkOut);
    }
    
    /**
     * Open a literal data packet, returning a stream to store the data inside
     * the packet as an indefiinite length stream. The stream is written out as a 
     * series of partial packets with a chunk size determined by the size of the
     * passed in buffer.The stream can be closed off by either calling close()
     * on the stream or close() on the generator.
     * <p>
     * <b>Note</b>: if the buffer is not a power of 2 in length only the largest power of 2
     * bytes worth of the buffer will be used.
     * 
     * @param out the stream we want the packet in
     * @param format the format we are using
     * @param name the name of the "file"
     * @param modificationTime the time of last modification we want stored.
     * @param buffer the buffer to use for collecting data to put into chunks.
     */
    public OutputStream open(
        OutputStream    out,
        char            format,
        String          name,
        Date            modificationTime,
        byte[]          buffer)
        throws IOException
    {
        if (pkOut != null)
        {
            throw new IllegalStateException("generator already in open state");
        }

        pkOut = new BCPGOutputStream(out, PacketTags.LITERAL_DATA, buffer);
        
        writeHeader(pkOut, format, name, modificationTime.getTime());

        return new LiteralDataWrappedStream(this, pkOut);
    }
    
    /**
     * Open a literal data packet for the passed in File object, returning
     * an output stream for saving the file contents. The stream can be closed off by either calling close()
     * on the stream or close() on the generator.
     * 
     * @param out
     * @param format
     * @param file
     * @return OutputStream
     * @throws IOException
     */
    public OutputStream open(
        OutputStream    out,
        char            format,
        File            file)
        throws IOException
    {
        if (pkOut != null)
        {
            throw new IllegalStateException("generator already in open state");
        }

        pkOut = new BCPGOutputStream(out, PacketTags.LITERAL_DATA, file.length() + 2 + file.getName().length() + 4, oldFormat);
        
        writeHeader(pkOut, format, file.getName(), file.lastModified());

        return new LiteralDataWrappedStream(this, pkOut);
    }
    
    /**
     * Close the literal data packet - this is equivalent to calling close on the stream
     * returned by the open() method.
     * 
     * @throws IOException
     */
    public void close()
        throws IOException
    {
        if (pkOut != null)
        {
            pkOut.finish();
            pkOut.flush();
            pkOut = null;
        }
    }

    private class LiteralDataWrappedStream
        extends FilterOutputStream
    {
        private final PGPLiteralDataGenerator _lGen;

        public LiteralDataWrappedStream(PGPLiteralDataGenerator lGen, OutputStream out)
        {
            super(out);
            _lGen = lGen;
        }

        public void close()
            throws IOException
        {
            _lGen.close();
        }
    }
}
