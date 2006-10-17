package org.bouncycastle.openpgp.test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.test.SimpleTest;

public class PGPCompressionTest 
    extends SimpleTest
{
    public void performTest()
        throws Exception
    {
        testCompression(PGPCompressedData.UNCOMPRESSED);
        testCompression(PGPCompressedData.ZIP);
        testCompression(PGPCompressedData.ZLIB);
        testCompression(PGPCompressedData.BZIP2);

        //
        // new style
        //
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator cPacket = new PGPCompressedDataGenerator(
                PGPCompressedData.ZIP);

        OutputStream out = cPacket.open(bOut, new byte[4]);

        out.write("hello world! !dlrow olleh".getBytes());

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

        if (!areEqual(bOut.toByteArray(), "hello world! !dlrow olleh".getBytes()))
        {
            fail("compression test failed");
        }
    }

    private void testCompression(
        int type)
        throws IOException, PGPException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator cPacket = new PGPCompressedDataGenerator(type);

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

        if (!areEqual(bOut.toByteArray(), "hello world!".getBytes()))
        {
            fail("compression test failed");
        }
    }

    public String getName()
    {
        return "PGPCompressionTest";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PGPCompressionTest());
    }
}
