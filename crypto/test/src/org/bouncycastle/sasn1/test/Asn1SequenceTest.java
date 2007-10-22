package org.bouncycastle.sasn1.test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Arrays;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.bouncycastle.sasn1.Asn1InputStream;
import org.bouncycastle.sasn1.Asn1Integer;
import org.bouncycastle.sasn1.Asn1ObjectIdentifier;
import org.bouncycastle.sasn1.Asn1Sequence;
import org.bouncycastle.sasn1.BerSequenceGenerator;
import org.bouncycastle.sasn1.DerSequenceGenerator;
import org.bouncycastle.util.encoders.Hex;

/**
 * @deprecated obsolete test case
 */
public class Asn1SequenceTest 
    extends TestCase 
{
    private static final byte[] seqData = Hex.decode("3006020100060129");
    private static final byte[] nestedSeqData = Hex.decode("300b0201000601293003020101");
    private static final byte[] expTagSeqData = Hex.decode("a1083006020100060129");
    private static final byte[] implTagSeqData = Hex.decode("a106020100060129");
    private static final byte[] nestedSeqExpTagData = Hex.decode("300d020100060129a1053003020101");
    private static final byte[] nestedSeqImpTagData = Hex.decode("300b020100060129a103020101");
    
    private static final byte[] berSeqData = Hex.decode("30800201000601290000");
    private static final byte[] berDerNestedSeqData = Hex.decode("308002010006012930030201010000");
    private static final byte[] berNestedSeqData = Hex.decode("3080020100060129308002010100000000");
    private static final byte[] berExpTagSeqData = Hex.decode("a180308002010006012900000000");
    
    public void testDerWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       DerSequenceGenerator  seqGen = new DerSequenceGenerator(bOut);
       
       seqGen.addObject(new Asn1Integer(BigInteger.valueOf(0)));
       
       seqGen.addObject(new Asn1ObjectIdentifier("1.1"));
       
       seqGen.close();

       assertTrue("basic DER writing test failed.", Arrays.equals(seqData, bOut.toByteArray()));
    }
 
    public void testNestedDerWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       DerSequenceGenerator  seqGen1 = new DerSequenceGenerator(bOut);
       
       seqGen1.addObject(new Asn1Integer(BigInteger.valueOf(0)));
       
       seqGen1.addObject(new Asn1ObjectIdentifier("1.1"));
       
       DerSequenceGenerator seqGen2 = new DerSequenceGenerator(seqGen1.getRawOutputStream());
       
       seqGen2.addObject(new Asn1Integer(BigInteger.valueOf(1)));
       
       seqGen2.close();
       
       seqGen1.close();

       assertTrue("nested DER writing test failed.", Arrays.equals(nestedSeqData, bOut.toByteArray()));
    }

    public void testDerExplicitTaggedSequenceWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       DerSequenceGenerator  seqGen = new DerSequenceGenerator(bOut, 1, true);
       
       seqGen.addObject(new Asn1Integer(BigInteger.valueOf(0)));
       
       seqGen.addObject(new Asn1ObjectIdentifier("1.1"));
       
       seqGen.close();

       assertTrue("explicit tag writing test failed.", Arrays.equals(expTagSeqData, bOut.toByteArray()));
    }
    
    public void testDerImplicitTaggedSequenceWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       DerSequenceGenerator  seqGen = new DerSequenceGenerator(bOut, 1, false);
       
       seqGen.addObject(new Asn1Integer(BigInteger.valueOf(0)));
       
       seqGen.addObject(new Asn1ObjectIdentifier("1.1"));
       
       seqGen.close();

       assertTrue("implicit tag writing test failed.", Arrays.equals(implTagSeqData, bOut.toByteArray()));
    }
    
    public void testNestedExplicitTagDerWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       DerSequenceGenerator  seqGen1 = new DerSequenceGenerator(bOut);
       
       seqGen1.addObject(new Asn1Integer(BigInteger.valueOf(0)));
       
       seqGen1.addObject(new Asn1ObjectIdentifier("1.1"));
       
       DerSequenceGenerator seqGen2 = new DerSequenceGenerator(seqGen1.getRawOutputStream(), 1, true);
       
       seqGen2.addObject(new Asn1Integer(BigInteger.valueOf(1)));
       
       seqGen2.close();
       
       seqGen1.close();

       assertTrue("nested explicit tagged DER writing test failed.", Arrays.equals(nestedSeqExpTagData, bOut.toByteArray()));
    }
    
    public void testNestedImplicitTagDerWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       DerSequenceGenerator  seqGen1 = new DerSequenceGenerator(bOut);
       
       seqGen1.addObject(new Asn1Integer(BigInteger.valueOf(0)));
       
       seqGen1.addObject(new Asn1ObjectIdentifier("1.1"));
       
       DerSequenceGenerator seqGen2 = new DerSequenceGenerator(seqGen1.getRawOutputStream(), 1, false);
       
       seqGen2.addObject(new Asn1Integer(BigInteger.valueOf(1)));
       
       seqGen2.close();
       
       seqGen1.close();

       assertTrue("nested implicit tagged DER writing test failed.", Arrays.equals(nestedSeqImpTagData, bOut.toByteArray()));
    }
    
    public void testBerWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       BerSequenceGenerator  seqGen = new BerSequenceGenerator(bOut);
       
       seqGen.addObject(new Asn1Integer(BigInteger.valueOf(0)));
       
       seqGen.addObject(new Asn1ObjectIdentifier("1.1"));
       
       seqGen.close();
       
       assertTrue("basic BER writing test failed.", Arrays.equals(berSeqData, bOut.toByteArray()));
    }

    public void testNestedBerDerWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       BerSequenceGenerator  seqGen1 = new BerSequenceGenerator(bOut);
       
       seqGen1.addObject(new Asn1Integer(BigInteger.valueOf(0)));
       
       seqGen1.addObject(new Asn1ObjectIdentifier("1.1"));
       
       DerSequenceGenerator seqGen2 = new DerSequenceGenerator(seqGen1.getRawOutputStream());
       
       seqGen2.addObject(new Asn1Integer(BigInteger.valueOf(1)));
       
       seqGen2.close();
       
       seqGen1.close();

       assertTrue("nested BER/DER writing test failed.", Arrays.equals(berDerNestedSeqData, bOut.toByteArray()));
    }
    
    public void testNestedBerWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       BerSequenceGenerator  seqGen1 = new BerSequenceGenerator(bOut);
       
       seqGen1.addObject(new Asn1Integer(BigInteger.valueOf(0)));
       
       seqGen1.addObject(new Asn1ObjectIdentifier("1.1"));
       
       BerSequenceGenerator seqGen2 = new BerSequenceGenerator(seqGen1.getRawOutputStream());
       
       seqGen2.addObject(new Asn1Integer(BigInteger.valueOf(1)));
       
       seqGen2.close();
       
       seqGen1.close();

       assertTrue("nested BER writing test failed.", Arrays.equals(berNestedSeqData, bOut.toByteArray()));
    }
    
    public void testDerReading()
        throws Exception
    {
        Asn1InputStream aIn = new Asn1InputStream(seqData);
        
        Asn1Sequence    seq = (Asn1Sequence)aIn.readObject();
        Object          o = null;
        int             count = 0;
        
        assertNotNull("null sequence returned", seq);
        
        while ((o = seq.readObject()) != null)
        {
            switch (count)
            {
            case 0:
                assertTrue(o instanceof Asn1Integer);
                break;
            case 1:
                assertTrue(o instanceof Asn1ObjectIdentifier);
                break;
            }
            count++;
        }
        
        assertEquals("wrong number of objects in sequence", 2, count);
    }

    public void testNestedReading(
        byte[] data)
        throws Exception
    {
        Asn1InputStream aIn = new Asn1InputStream(data);
        
        Asn1Sequence    seq = (Asn1Sequence)aIn.readObject();
        Object          o = null;
        int             count = 0;
        
        assertNotNull("null sequence returned", seq);
        
        while ((o = seq.readObject()) != null)
        {
            switch (count)
            {
            case 0:
                assertTrue(o instanceof Asn1Integer);
                break;
            case 1:
                assertTrue(o instanceof Asn1ObjectIdentifier);
                break;
            case 2:
                assertTrue(o instanceof Asn1Sequence);
                
                Asn1Sequence s = (Asn1Sequence)o;
                
                s.readObject();
                
                break;
            }
            count++;
        }
        
        assertEquals("wrong number of objects in sequence", 3, count);
    }
    
    public void testNestedDerReading()
        throws Exception
    {
        testNestedReading(nestedSeqData);
    }
    
    public void testBerReading()
        throws Exception
    {
        Asn1InputStream aIn = new Asn1InputStream(berSeqData);
        
        Asn1Sequence    seq = (Asn1Sequence)aIn.readObject();
        Object          o = null;
        int             count = 0;
        
        assertNotNull("null sequence returned", seq);
        
        while ((o = seq.readObject()) != null)
        {
            switch (count)
            {
            case 0:
                assertTrue(o instanceof Asn1Integer);
                break;
            case 1:
                assertTrue(o instanceof Asn1ObjectIdentifier);
                break;
            }
            count++;
        }
        
        assertEquals("wrong number of objects in sequence", 2, count);
    }
    
    public void testNestedBerDerReading()
        throws Exception
    {
        testNestedReading(berDerNestedSeqData);
    }
    
    public void testNestedBerReading()
        throws Exception
    {
        testNestedReading(berNestedSeqData);
    }
    
    public void testBerExplicitTaggedSequenceWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       BerSequenceGenerator  seqGen = new BerSequenceGenerator(bOut, 1, true);
       
       seqGen.addObject(new Asn1Integer(BigInteger.valueOf(0)));
       
       seqGen.addObject(new Asn1ObjectIdentifier("1.1"));
       
       seqGen.close();
      
       assertTrue("explicit BER tag writing test failed.", Arrays.equals(berExpTagSeqData, bOut.toByteArray()));
    }
    
    public static Test suite()
    {
        return new TestSuite(Asn1SequenceTest.class);
    }
}
