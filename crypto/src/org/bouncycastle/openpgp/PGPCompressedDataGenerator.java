package org.bouncycastle.openpgp;

import java.io.IOException;
import java.io.OutputStream;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

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
    private DeflaterOutputStream    dOut;
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
        if (algorithm != PGPCompressedData.ZIP && algorithm != PGPCompressedData.ZLIB)
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

            dOut = new DeflaterOutputStream(pkOut, new Deflater(compression, true));
        }
        else
        {
            pkOut = new BCPGOutputStream(out, PacketTags.COMPRESSED_DATA);
            
            pkOut.write(PGPCompressedData.ZLIB);
            
            dOut = new DeflaterOutputStream(pkOut, new Deflater(compression));
        }
        
        return dOut;
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
        
        dOut.finish();
        dOut.flush();
        pkOut.finish();
        pkOut.flush();
        out.flush();
    }
}
