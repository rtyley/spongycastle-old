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
    
    private OutputStream            out;
    private DeflaterOutputStream    dOut;
    private BCPGOutputStream        pkOut;
    
    public PGPCompressedDataGenerator(
        int                    algorithm)
    {
        if (algorithm != PGPCompressedData.ZIP && algorithm != PGPCompressedData.ZLIB)
        {
            throw new IllegalArgumentException("unknown compression algorithm");
        }
        
        this.algorithm = algorithm;
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

            dOut = new DeflaterOutputStream(pkOut, new Deflater(Deflater.DEFAULT_COMPRESSION, true));
        }
        else
        {
            pkOut = new BCPGOutputStream(out, PacketTags.COMPRESSED_DATA);
            
            pkOut.write(PGPCompressedData.ZLIB);
            
            dOut = new DeflaterOutputStream(pkOut, new Deflater(Deflater.DEFAULT_COMPRESSION));
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
        
        dOut.flush();
        dOut.finish();
        pkOut.flush();
        out.flush();
    }
}
