package org.bouncycastle.cms;

import java.io.IOException;
import java.io.OutputStream;
import java.util.zip.DeflaterOutputStream;

import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequenceGenerator;

/**
 * General class for generating a compressed CMS message stream.
 * <p>
 * A simple example of usage.
 * </p>
 * <pre>
 *      CMSCompressedDataStreamGenerator gen = new CMSCompressedDataStreamGenerator();
 *      
 *      OutputStream cOut = gen.open(outputStream, CMSCompressedDataStreamGenerator.ZLIB);
 *      
 *      cOut.write(data);
 *      
 *      cOut.close();
 * </pre>
 */
public class CMSCompressedDataStreamGenerator
{
    public static final String  ZLIB    = "1.2.840.113549.1.9.16.3.8";

    private int _bufferSize;
    
    /**
     * base constructor
     */
    public CMSCompressedDataStreamGenerator()
    {
    }

    /**
     * Set the underlying string size for encapsulated data
     *
     * @param bufferSize length of octet strings to buffer the data.
     */
    public void setBufferSize(
        int bufferSize)
    {
        _bufferSize = bufferSize;
    }

    public OutputStream open(
        OutputStream out,
        String       compressionOID) 
        throws IOException
    {
        return open(out, CMSObjectIdentifiers.data.getId(), compressionOID);
    }
    
    public OutputStream open(
        OutputStream  out,        
        String        contentOID,
        String        compressionOID) 
        throws IOException
    {
        BERSequenceGenerator sGen = new BERSequenceGenerator(out);
        
        sGen.addObject(CMSObjectIdentifiers.compressedData);
        
        //
        // Compressed Data
        //
        BERSequenceGenerator cGen = new BERSequenceGenerator(sGen.getRawOutputStream(), 0, true);
        
        cGen.addObject(new DERInteger(0));
        
        //
        // AlgorithmIdentifier
        //
        DERSequenceGenerator algGen = new DERSequenceGenerator(cGen.getRawOutputStream());
        
        algGen.addObject(new DERObjectIdentifier(ZLIB));

        algGen.close();
        
        //
        // Encapsulated ContentInfo
        //
        BERSequenceGenerator eiGen = new BERSequenceGenerator(cGen.getRawOutputStream());
        
        eiGen.addObject(new DERObjectIdentifier(contentOID));

        OutputStream octetStream = CMSUtils.createBEROctetOutputStream(
            eiGen.getRawOutputStream(), 0, true, _bufferSize);
        
        return new CmsCompressedOutputStream(
            new DeflaterOutputStream(octetStream), sGen, cGen, eiGen);
    }
    
    private class CmsCompressedOutputStream
        extends OutputStream
    {
        private DeflaterOutputStream _out;
        private BERSequenceGenerator _sGen;
        private BERSequenceGenerator _cGen;
        private BERSequenceGenerator _eiGen;
        
        CmsCompressedOutputStream(
            DeflaterOutputStream out,
            BERSequenceGenerator sGen,
            BERSequenceGenerator cGen,
            BERSequenceGenerator eiGen)
        {
            _out = out;
            _sGen = sGen;
            _cGen = cGen;
            _eiGen = eiGen;
        }
        
        public void write(
            int b)
            throws IOException
        {
            _out.write(b); 
        }
        
        
        public void write(
            byte[] bytes,
            int    off,
            int    len)
            throws IOException
        {
            _out.write(bytes, off, len);
        }
        
        public void write(
            byte[] bytes)
            throws IOException
        {
            _out.write(bytes);
        }
        
        public void close()
            throws IOException
        {
            _out.close();
            _eiGen.close();
            _cGen.close();
            _sGen.close();
        }
    }
}
