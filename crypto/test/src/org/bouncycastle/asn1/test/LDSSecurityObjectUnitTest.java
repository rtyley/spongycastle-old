package org.bouncycastle.asn1.test;

import java.io.IOException;
import java.util.Random;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.icao.DataGroupHash;
import org.bouncycastle.asn1.icao.LDSSecurityObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.test.SimpleTest;

public class LDSSecurityObjectUnitTest 
    extends SimpleTest
{
    public String getName()
    {
        return "LDSSecurityObject";
    }
    
    private byte[] generateHash()
    {
        Random rand = new Random();
        byte[] bytes = new byte[20];
        
        for (int i = 0; i != bytes.length; i++)
        {
            bytes[i] = (byte)rand.nextInt();
        }
        
        return bytes;
    }
    
    public void performTest() 
        throws Exception
    {
        AlgorithmIdentifier  algoId = new AlgorithmIdentifier("1.3.14.3.2.26");
        DataGroupHash[] datas = new DataGroupHash[2];
      
        datas[0] = new DataGroupHash(1, new DEROctetString(generateHash()));
        datas[1] = new DataGroupHash(2, new DEROctetString(generateHash()));
        
        LDSSecurityObject so = new LDSSecurityObject(algoId, datas);

        checkConstruction(so, algoId, datas);
        
        
        so = LDSSecurityObject.getInstance(null);
        
        if (so != null)
        {
            fail("null getInstance() failed.");
        }
        
        try
        {
            LDSSecurityObject.getInstance(new Object());
            
            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
        
        try
        {
            ASN1EncodableVector v = new ASN1EncodableVector();
            
            new LDSSecurityObject(new DERSequence(v));
            
            fail("constructor failed to detect empty sequence.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
        
        try
        {
            new LDSSecurityObject(algoId, new DataGroupHash[1]);
            
            fail("constructor failed to detect small DataGroupHash array.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
        
        try
        {
            new LDSSecurityObject(algoId, new DataGroupHash[LDSSecurityObject.ub_DataGroups + 1]);
            
            fail("constructor failed to out of bounds DataGroupHash array.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
        LDSSecurityObject so,
        AlgorithmIdentifier digestAlgorithmIdentifier, 
        DataGroupHash[]       datagroupHash) 
        throws IOException
    {
        checkStatement(so, digestAlgorithmIdentifier, datagroupHash);
        
        so = LDSSecurityObject.getInstance(so);
        
        checkStatement(so, digestAlgorithmIdentifier, datagroupHash);
        
        ASN1InputStream aIn = new ASN1InputStream(so.toASN1Object().getEncoded());

        ASN1Sequence seq = (ASN1Sequence)aIn.readObject();
        
        so = LDSSecurityObject.getInstance(seq);
        
        checkStatement(so, digestAlgorithmIdentifier, datagroupHash);
    }

    private void checkStatement(
        LDSSecurityObject so,
        AlgorithmIdentifier digestAlgorithmIdentifier, 
        DataGroupHash[]       datagroupHash)
    {
        if (digestAlgorithmIdentifier != null)
        {
            if (!so.getDigestAlgorithmIdentifier().equals(digestAlgorithmIdentifier))
            {
                fail("ids don't match.");
            }
        }
        else if (so.getDigestAlgorithmIdentifier() != null)
        {
            fail("digest algorithm Id found when none expected.");
        }
        
        if (datagroupHash != null)
        {
            DataGroupHash[] datas = so.getDatagroupHash();
            
            for (int i = 0; i != datas.length; i++)
            {
                if (!datagroupHash[i].equals(datas[i]))
                {
                    fail("name registration authorities don't match.");
                }
            }
        }
        else if (so.getDatagroupHash() != null)
        {
            fail("data hash groups found when none expected.");
        }
    }
    
    public static void main(
        String[]    args)
    {
        runTest(new LDSSecurityObjectUnitTest());
    }
}
