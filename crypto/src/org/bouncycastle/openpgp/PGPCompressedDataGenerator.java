package org.bouncycastle.openpgp;

import org.bouncycastle.apache.bzip2.CBZip2OutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.PacketTags;

import java.io.IOException;
import java.io.OutputStream;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

/**
 *class for producing compressed data packets.
 */
public class PGPCompressedDataGenerator 
    implements CompressionAlgorithmTags
{
    private int                     algorithm;
    private int                     compression;
    
    private OutputStream            out;
    private OutputStream            dOut;
    private BCPGOutputStream        pkOut;
    
    public PGPCompressedDataGenerator(
        int                    algorithm)
    {
        this(algorithm, Deflater.DEFAULT_COMPRESSION);
    }
                    
    public PGPCompressedDataGenerator(
        int                    algorithm,
        int                    compression)
    {
        if (algorithm != PGPCompressedData.UNCOMPRESSED
            && algorithm != PGPCompressedData.ZIP
            && algorithm != PGPCompressedData.ZLIB
            && algorithm != PGPCompressedData.BZIP2)
        {
            throw new IllegalArgumentException("unknown compression algorithm");
        }

        if (compression != Deflater.DEFAULT_COMPRESSION)
        {
            if ((compression < 0) || (compression > 9))
            {
                throw new IllegalArgumentException("unknown compression level: " + compression);
            }
        }
        
        this.algorithm = algorithm;
        this.compression = compression;
    }

    /**
     * Return an outputstream which will save the data being written to 
     * the compressed object. The stream can be closed off by either calling close() 
     * on the stream or close() on the generator.
     * 
     * @param out
     * @return OutputStream
     * @throws IOException, IllegalStateException
     */        
    public OutputStream open(
        OutputStream    out)
        throws IOException
    {
        if (dOut != null)
        {
            throw new IllegalStateException("generator already in open state");
        }

        this.out = out;

        switch (algorithm)
        {
        case PGPCompressedData.ZIP:
            pkOut = new BCPGOutputStream(out, PacketTags.COMPRESSED_DATA);
            pkOut.write(PGPCompressedData.ZIP);
            dOut = new DeflaterOutputStream(pkOut, new Deflater(compression, true));
            break;
        case PGPCompressedData.ZLIB:
            pkOut = new BCPGOutputStream(out, PacketTags.COMPRESSED_DATA);
            pkOut.write(PGPCompressedData.ZLIB);
            dOut = new DeflaterOutputStream(pkOut, new Deflater(compression));
            break;
        case BZIP2:
            pkOut = new BCPGOutputStream(out, PacketTags.COMPRESSED_DATA);
            pkOut.write(PGPCompressedData.BZIP2);
            dOut = new CBZip2OutputStream(pkOut);
            break;
        case PGPCompressedData.UNCOMPRESSED:
            pkOut = new BCPGOutputStream(out, PacketTags.COMPRESSED_DATA);
            pkOut.write(PGPCompressedData.UNCOMPRESSED);
            dOut = pkOut;
            break;
        default:
            throw new IllegalStateException("generator not initialised");
        }

        return new CompressedWrappedStream(this, dOut);
    }
    
    /**
     * Return an outputstream which will compress the data as it is written
     * to it. The stream will be written out in chunks according to the size of the
     * passed in buffer and can be closed off by either calling close() on the stream or close() on
     * the generator.
     * <p>
     * <b>Note</b>: if the buffer is not a power of 2 in length only the largest power of 2
     * bytes worth of the buffer will be used.
     * </p>
     * <p>
     * <b>Note</b>: using this may break compatability with RFC 1991 compliant tools. Only recent OpenPGP
     * implementations are capable of accepting these streams.
     * </p>
     * 
     * @param out
     * @param buffer the buffer to use.
     * @return OutputStream
     * @throws IOException
     * @throws PGPException
     */
    public OutputStream open(
        OutputStream    out,
        byte[]          buffer)
        throws IOException, PGPException
    {
        if (dOut != null)
        {
            throw new IllegalStateException("generator already in open state");
        }
                
        this.out = out;

        switch (algorithm)
        {
        case PGPCompressedData.ZIP:
            pkOut = new BCPGOutputStream(out, PacketTags.COMPRESSED_DATA, buffer);
            pkOut.write(PGPCompressedData.ZIP);
            dOut = new DeflaterOutputStream(pkOut, new Deflater(compression, true));
            break;
        case PGPCompressedData.ZLIB:
            pkOut = new BCPGOutputStream(out, PacketTags.COMPRESSED_DATA, buffer);
            pkOut.write(PGPCompressedData.ZLIB);
            dOut = new DeflaterOutputStream(pkOut, new Deflater(compression));
            break;
        case PGPCompressedData.BZIP2:
            pkOut = new BCPGOutputStream(out, PacketTags.COMPRESSED_DATA, buffer);
            pkOut.write(PGPCompressedData.BZIP2);
            dOut = new CBZip2OutputStream(pkOut);
            break;
        case PGPCompressedData.UNCOMPRESSED:
            pkOut = new BCPGOutputStream(out, PacketTags.COMPRESSED_DATA, buffer);
            pkOut.write(PGPCompressedData.UNCOMPRESSED);
            dOut = pkOut;
            break;
        default:
            throw new IllegalStateException("generator not initialised");
        }

        return new CompressedWrappedStream(this, dOut);
    }
    
    /**
     * Close the compressed object - this is equivalent to calling close on the stream
     * returned by the open() method.
     * 
     * @throws IOException
     */
    public void close()
        throws IOException
    {
        localClose();
    }

    public void localClose()
        throws IOException
    {
        if (dOut == null)
        {
            throw new IOException("generator not opened.");
        }

        if (dOut instanceof DeflaterOutputStream)
        {
            DeflaterOutputStream dfOut = (DeflaterOutputStream)dOut;

            dfOut.finish();
        }
        else if (dOut instanceof CBZip2OutputStream)
        {
            CBZip2OutputStream cbOut = (CBZip2OutputStream)dOut;

            cbOut.finish();
        }

        dOut.flush();

        pkOut.finish();
        pkOut.flush();
        out.flush();

        dOut = null;
    }

    private class CompressedWrappedStream
        extends OutputStream
    {
        private final PGPCompressedDataGenerator _cGen;
        private final OutputStream _out;

        public CompressedWrappedStream(PGPCompressedDataGenerator cGen, OutputStream out)
        {
            _cGen = cGen;
            _out = out;
        }

        public void write(byte[] bytes)
            throws IOException
        {
            _out.write(bytes);
        }

        public void write(byte[] bytes, int offset, int length)
            throws IOException
        {
            _out.write(bytes, offset, length);
        }

        public void write(int b)
            throws IOException
        {
            _out.write(b);
        }

        public void flush()
            throws IOException
        {
            _out.flush();
        }

        public void close()
            throws IOException
        {
            _cGen.localClose();
        }
    }
}
