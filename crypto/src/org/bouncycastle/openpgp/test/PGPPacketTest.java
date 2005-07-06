package org.bouncycastle.openpgp.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Date;
import java.util.Random;

import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class PGPPacketTest
    implements Test
{
    private static int MAX = 32000;
    
    private TestResult readBackTest(
        PGPLiteralDataGenerator generator)
        throws IOException
    {
        Random                  rand = new Random();
        byte[]                  buf = new byte[MAX];
        
        rand.nextBytes(buf);
        
        for (int i = 1; i != MAX; i++)
        {
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
            
            OutputStream            out = generator.open(bOut, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, i, new Date());
            
            out.write(buf, 0, i);
            
            generator.close();
            
            PGPObjectFactory        fact = new PGPObjectFactory(bOut.toByteArray());
            
            PGPLiteralData          data = (PGPLiteralData)fact.nextObject();
            
            InputStream             in = data.getInputStream();

            for (int count = 0; count != i; count++)
            {
                if (in.read() != (buf[count] & 0xff))
                {
                    return new SimpleTestResult(false, getName() + ": failed readback test - length = " + i);
                }
            }
        }
        
        return new SimpleTestResult(true, getName() + ": Okay");
    }
    
    public TestResult perform()
    {
        try
        {
            PGPLiteralDataGenerator oldGenerator = new PGPLiteralDataGenerator(true);

            TestResult res = readBackTest(oldGenerator);
            if (!res.isSuccessful())
            {
                return res;
            }
            
            PGPLiteralDataGenerator newGenerator = new PGPLiteralDataGenerator(false);
            
            return res = readBackTest(newGenerator);
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": exception - " + e.toString());
        }
    }

    public String getName()
    {
        return "PGPPacketTest";
    }

    public static void main(
        String[]    args)
    {
        Test            test = new PGPPacketTest();
        TestResult      result = test.perform();

        System.out.println(result.toString());
    }
}
