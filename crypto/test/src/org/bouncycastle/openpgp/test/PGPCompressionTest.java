package org.bouncycastle.openpgp.test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class PGPCompressionTest implements Test
{
    private boolean notEqual(byte[] b1, byte[] b2)
    {
        if (b1.length != b2.length)
        {
            return true;
        }

        for (int i = 0; i != b2.length; i++)
        {
            if (b1[i] != b2[i])
            {
                return true;
            }
        }

        return false;
    }

    public TestResult perform()
    {
        try
        {
            //
            // standard
            //
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            PGPCompressedDataGenerator cPacket = new PGPCompressedDataGenerator(
                    PGPCompressedData.ZIP);

            OutputStream out = cPacket.open(bOut);

            out.write("hello world!".getBytes());

            cPacket.close();

            PGPObjectFactory pgpFact = new PGPObjectFactory(bOut.toByteArray());
            PGPCompressedData c1 = (PGPCompressedData)pgpFact.nextObject();
            InputStream pIn = c1.getDataStream();

            bOut.reset();

            int ch;
            while ((ch = pIn.read()) >= 0)
            {
                bOut.write(ch);
            }

            if (notEqual(bOut.toByteArray(), "hello world!".getBytes()))
            {
                return new SimpleTestResult(false, getName() + ": compression test failed");
            }

            //
            // new style
            //
            bOut = new ByteArrayOutputStream();
            cPacket = new PGPCompressedDataGenerator(
                    PGPCompressedData.ZIP);

            out = cPacket.open(bOut, new byte[4]);

            out.write("hello world! !dlrow olleh".getBytes());

            cPacket.close();

            pgpFact = new PGPObjectFactory(bOut.toByteArray());
            c1 = (PGPCompressedData)pgpFact.nextObject();
            pIn = c1.getDataStream();

            bOut.reset();

            while ((ch = pIn.read()) >= 0)
            {
                bOut.write(ch);
            }

            if (notEqual(bOut.toByteArray(), "hello world! !dlrow olleh".getBytes()))
            {
                return new SimpleTestResult(false, getName() + ": compression test failed");
            }
            
            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return new SimpleTestResult(false, getName() + ": exception - " + e.toString());
        }
    }

    public String getName()
    {
        return "PGPCompressionTest";
    }

    public static void main(String[] args)
    {
        Test test = new PGPCompressionTest();
        TestResult result = test.perform();

        System.out.println(result.toString());
    }
}
