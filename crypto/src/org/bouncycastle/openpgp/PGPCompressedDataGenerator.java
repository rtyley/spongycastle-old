package org.bouncycastle.openpgp;

import java.io.IOException;
import java.io.OutputStream;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import org.apache.tools.bzip2.CBZip2OutputStream;

import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.PacketTags;

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
     * the compressed object.
     * 
     * @param out
     * @return OutputStream
     * @throws IOException
     */        
    public OutputStream open(
        OutputStream    out)
        throws IOException
    {
        this.out = out;

        if (algorithm == PGPCompressedData.ZIP)
        {
            pkOut = new BCPGOutputStream(out, PacketTags.COMPRESSED_DATA);
            
            pkOut.write(PGPCompressedData.ZIP);

            return dOut = new DeflaterOutputStream(pkOut, new Deflater(compression, true));
        }

        if (algorithm == PGPCompressedData.ZLIB)
        {
            pkOut = new BCPGOutputStream(out, PacketTags.COMPRESSED_DATA);
            
            pkOut.write(PGPCompressedData.ZLIB);
            
            return dOut = new DeflaterOutputStream(pkOut, new Deflater(compression));
        }

        if (algorithm == BZIP2)
        {
            pkOut = new BCPGOutputStream(out, PacketTags.COMPRESSED_DATA);

            pkOut.write(PGPCompressedData.BZIP2);

            return dOut = new CBZip2OutputStream(pkOut);
        }

        if (algorithm == PGPCompressedData.UNCOMPRESSED)
        {
            pkOut = new BCPGOutputStream(out, PacketTags.COMPRESSED_DATA);

            pkOut.write(PGPCompressedData.UNCOMPRESSED);

            return dOut = pkOut;
        }

        throw new IllegalStateException("generator not initialised");
    }
    
    /**
     * Return an outputstream which will compress the data as it is written
     * to it. The stream will be written out in chunks according to the size of the
     * passed in buffer.
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
        this.out = out;

        if (algorithm == PGPCompressedData.ZIP)
        {
            pkOut = new BCPGOutputStream(out, PacketTags.COMPRESSED_DATA, buffer);
            
            pkOut.write(PGPCompressedData.ZIP);

            return dOut = new DeflaterOutputStream(pkOut, new Deflater(compression, true));
        }

        if (algorithm == PGPCompressedData.ZLIB)
        {
            pkOut = new BCPGOutputStream(out, PacketTags.COMPRESSED_DATA, buffer);
            
            pkOut.write(PGPCompressedData.ZLIB);
            
            return dOut = new DeflaterOutputStream(pkOut, new Deflater(compression));
        }

        if (algorithm == PGPCompressedData.BZIP2)
        {
            pkOut = new BCPGOutputStream(out, PacketTags.COMPRESSED_DATA, buffer);

            pkOut.write(PGPCompressedData.BZIP2);

            return dOut = new CBZip2OutputStream(pkOut);
        }

        if (algorithm == PGPCompressedData.UNCOMPRESSED)
        {
            pkOut = new BCPGOutputStream(out, PacketTags.COMPRESSED_DATA, buffer);

            pkOut.write(PGPCompressedData.UNCOMPRESSED);

            return dOut = pkOut;
        }


        throw new IllegalStateException("generator not initialised");
    }
    
    /**
     * Close the compressed object.
     * 
     * @throws IOException
     */
    public void close()
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
    }
}
