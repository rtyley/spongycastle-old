package org.bouncycastle.cms;

import java.io.IOException;
import java.io.OutputStream;
import java.util.zip.DeflaterOutputStream;

import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.sasn1.Asn1Integer;
import org.bouncycastle.sasn1.Asn1ObjectIdentifier;
import org.bouncycastle.sasn1.BerOctetStringGenerator;
import org.bouncycastle.sasn1.BerSequenceGenerator;
import org.bouncycastle.sasn1.DerSequenceGenerator;

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

    /**
     * base constructor
     */
    public CMSCompressedDataStreamGenerator()
    {
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
        BerSequenceGenerator sGen = new BerSequenceGenerator(out);
        
        sGen.addObject(new Asn1ObjectIdentifier(CMSObjectIdentifiers.compressedData.getId()));
        
        //
        // Compressed Data
        //
        BerSequenceGenerator cGen = new BerSequenceGenerator(sGen.getRawOutputStream(), 0, true);
        
        cGen.addObject(new Asn1Integer(0));
        
        //
        // AlgorithmIdentifier
        //
        DerSequenceGenerator algGen = new DerSequenceGenerator(cGen.getRawOutputStream());
        
        algGen.addObject(new Asn1ObjectIdentifier(ZLIB));

        algGen.close();
        
        //
        // Encapsulated ContentInfo
        //
        BerSequenceGenerator eiGen = new BerSequenceGenerator(cGen.getRawOutputStream());
        
        eiGen.addObject(new Asn1ObjectIdentifier(contentOID));
        
        BerOctetStringGenerator octGen = new BerOctetStringGenerator(eiGen.getRawOutputStream(), 0, true);
        
        return new CmsCompressedOutputStream(new DeflaterOutputStream(octGen.getOctetOutputStream()), sGen, cGen, eiGen);
    }
    
    private class CmsCompressedOutputStream
        extends OutputStream
    {
        private DeflaterOutputStream _out;
        private BerSequenceGenerator _sGen;
        private BerSequenceGenerator _cGen;
        private BerSequenceGenerator _eiGen;
        
        CmsCompressedOutputStream(
            DeflaterOutputStream out,
            BerSequenceGenerator sGen,
            BerSequenceGenerator cGen,
            BerSequenceGenerator eiGen)
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
