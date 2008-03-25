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
    implements CompressionAlgorithmTags, StreamGenerator
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
     * the compressed object.
     * <p>
     * The stream created can be closed off by either calling close()
     * on the stream or close() on the generator. Closing the returned
     * stream does not close off the OutputStream parameter out.
     * 
     * @param out underlying OutputStream to be used.
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

        return new WrappedGeneratorStream(dOut, this);
    }
    
    /**
     * Return an outputstream which will compress the data as it is written
     * to it. The stream will be written out in chunks according to the size of the
     * passed in buffer.
     * <p>
     * The stream created can be closed off by either calling close()
     * on the stream or close() on the generator. Closing the returned
     * stream does not close off the OutputStream parameter out.
     * <p>
     * <b>Note</b>: if the buffer is not a power of 2 in length only the largest power of 2
     * bytes worth of the buffer will be used.
     * </p>
     * <p>
     * <b>Note</b>: using this may break compatability with RFC 1991 compliant tools. Only recent OpenPGP
     * implementations are capable of accepting these streams.
     * </p>
     * 
     * @param out underlying OutputStream to be used.
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

        return new WrappedGeneratorStream(dOut, this);
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
        if (dOut != null)
        {
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
            pkOut = null;
            out = null;
        }
    }
}
