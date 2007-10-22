package org.bouncycastle.sasn1.test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.sasn1.Asn1InputStream;
import org.bouncycastle.sasn1.Asn1Integer;
import org.bouncycastle.sasn1.Asn1ObjectIdentifier;
import org.bouncycastle.sasn1.Asn1OctetString;
import org.bouncycastle.sasn1.Asn1Sequence;
import org.bouncycastle.sasn1.BerOctetString;
import org.bouncycastle.sasn1.BerOctetStringGenerator;
import org.bouncycastle.sasn1.BerSequence;
import org.bouncycastle.sasn1.BerSequenceGenerator;
import org.bouncycastle.sasn1.BerTag;
import org.bouncycastle.sasn1.DerSequenceGenerator;
import org.bouncycastle.sasn1.cms.CompressedDataParser;
import org.bouncycastle.sasn1.cms.ContentInfoParser;

/**
 * @deprecated obsolete test case
 */
public class OctetStringTest 
    extends TestCase 
{
    public void testReadingWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       BerOctetStringGenerator octGen = new BerOctetStringGenerator(bOut);
       
       OutputStream out = octGen.getOctetOutputStream();
       
       out.write(new byte[] { 1, 2, 3, 4 });
       out.write(new byte[4]);
       
       out.close();
       
       Asn1InputStream aIn = new Asn1InputStream(bOut.toByteArray());
       
       BerOctetString s = (BerOctetString)aIn.readObject();
       
       InputStream in = s.getOctetStream();
       int         count = 0;
       
       while (in.read() >= 0)
       {
           count++;
       }

       assertEquals(8, count);
    }
    
    public void testReadingWritingZeroInLength()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       BerOctetStringGenerator octGen = new BerOctetStringGenerator(bOut);
       
       OutputStream out = octGen.getOctetOutputStream();
       
       out.write(new byte[] { 1, 2, 3, 4 });
       out.write(new byte[512]);  // forces a zero to appear in length
       
       out.close();
       
       Asn1InputStream aIn = new Asn1InputStream(bOut.toByteArray());
       
       BerOctetString s = (BerOctetString)aIn.readObject();
       
       InputStream in = s.getOctetStream();
       int         count = 0;
       
       while (in.read() >= 0)
       {
           count++;
       }
    
       assertEquals(516, count);
    }
    
    public void testReadingWritingNested()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       BerSequenceGenerator sGen = new BerSequenceGenerator(bOut);
       BerOctetStringGenerator octGen = new BerOctetStringGenerator(sGen.getRawOutputStream());
       
       OutputStream out = octGen.getOctetOutputStream();
       
       BerSequenceGenerator inSGen = new BerSequenceGenerator(out);
       
       BerOctetStringGenerator inOctGen = new BerOctetStringGenerator(inSGen.getRawOutputStream());
       
       OutputStream inOut = inOctGen.getOctetOutputStream();
       
       inOut.write(new byte[] { 1, 2, 3, 4 });
       inOut.write(new byte[10]);
       
       inOut.close();
       
       inSGen.close();
       
       out.close();
       
       sGen.close();
       
       Asn1InputStream aIn = new Asn1InputStream(bOut.toByteArray());
       
       BerSequence     sq = (BerSequence)aIn.readObject();
       
       BerOctetString s = (BerOctetString)sq.readObject();
       
       Asn1InputStream aIn2 = new Asn1InputStream(s.getOctetStream());
       
       BerSequence sq2 = (BerSequence)aIn2.readObject();
       
       BerOctetString inS = (BerOctetString)sq2.readObject();
       
       InputStream in = inS.getOctetStream();
       int         count = 0;
       
       while (in.read() >= 0)
       {
           count++;
       }
    
       assertEquals(14, count);
    }
    
    public void testNestedStructure()
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        BerSequenceGenerator sGen = new BerSequenceGenerator(bOut);
        
        sGen.addObject(new Asn1ObjectIdentifier(CMSObjectIdentifiers.compressedData.getId()));
        
        BerSequenceGenerator cGen = new BerSequenceGenerator(sGen.getRawOutputStream(), 0, true);
        
        cGen.addObject(new Asn1Integer(0));
        
        //
        // AlgorithmIdentifier
        //
        DerSequenceGenerator algGen = new DerSequenceGenerator(cGen.getRawOutputStream());
        
        algGen.addObject(new Asn1ObjectIdentifier("1.2"));

        algGen.close();
        
        //
        // Encapsulated ContentInfo
        //
        BerSequenceGenerator eiGen = new BerSequenceGenerator(cGen.getRawOutputStream());
        
        eiGen.addObject(new Asn1ObjectIdentifier("1.1"));
        
        BerOctetStringGenerator octGen = new BerOctetStringGenerator(eiGen.getRawOutputStream(), 0, true);
        
        //
        // output containing zeroes
        //
        OutputStream out = octGen.getOctetOutputStream();
        
        out.write(new byte[] { 1, 2, 3, 4 });
        out.write(new byte[4]);
        out.write(new byte[20]);
        
        out.close();
        eiGen.close();
        cGen.close();
        sGen.close();
        
        //
        // reading back
        //
        Asn1InputStream aIn = new Asn1InputStream(bOut.toByteArray());

        ContentInfoParser cp = new ContentInfoParser((Asn1Sequence)aIn.readObject());
        
        CompressedDataParser  comData = new CompressedDataParser((Asn1Sequence)cp.getContent(BerTag.SEQUENCE));
        ContentInfoParser     content = comData.getEncapContentInfo();

        Asn1OctetString bytes = (Asn1OctetString)content.getContent(BerTag.OCTET_STRING);

        InputStream in = bytes.getOctetStream();
        int         count = 0;
        
        while (in.read() >= 0)
        {
            count++;
        }

        assertEquals(28, count);
    }
    
    public static Test suite()
    {
        return new TestSuite(OctetStringTest.class);
    }
}
