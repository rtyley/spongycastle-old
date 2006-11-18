package org.bouncycastle.openpgp.test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.UncloseableOutputStream;

public class PGPPBETest
    extends SimpleTest
{
    private static final Date TEST_DATE = new Date(1062200111000L);

    byte[] enc1 = Base64.decode(
            "jA0EAwMC5M5wWBP2HBZgySvUwWFAmMRLn7dWiZN6AkQMvpE3b6qwN3SSun7zInw2"
          + "hxxdgFzVGfbjuB8w");

    byte[] enc1crc = Base64.decode("H66L");

    char[] pass = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd' };

    /**
     * decrypt the passed in message stream
     */
    private byte[] decryptMessage(
        byte[]    message,
        Date      date)
        throws Exception
    {
        PGPObjectFactory         pgpF = new PGPObjectFactory(message);
        PGPEncryptedDataList     enc = (PGPEncryptedDataList)pgpF.nextObject();
        PGPPBEEncryptedData      pbe = (PGPPBEEncryptedData)enc.get(0);

        InputStream clear = pbe.getDataStream(pass, "BC");
        
        PGPObjectFactory         pgpFact = new PGPObjectFactory(clear);
        PGPCompressedData        cData = (PGPCompressedData)pgpFact.nextObject();

        pgpFact = new PGPObjectFactory(cData.getDataStream());
        
        PGPLiteralData           ld = (PGPLiteralData)pgpFact.nextObject();
        
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        if (!ld.getFileName().equals("test.txt")
            && !ld.getFileName().equals("_CONSOLE"))
        {
            fail("wrong filename in packet");
        }
        if (!ld.getModificationTime().equals(date))
        {
            fail("wrong modification time in packet: " + ld.getModificationTime().getTime() + " " + date.getTime());
        }

        InputStream              unc = ld.getInputStream();
        int                      ch;
        
        while ((ch = unc.read()) >= 0)
        {
            bOut.write(ch);
        }

        if (pbe.isIntegrityProtected() && !pbe.verify())
        {
            fail("integrity check failed");
        }

        return bOut.toByteArray();
    }

    public void performTest()
        throws Exception
    {
        byte[] out = decryptMessage(enc1, TEST_DATE);

        if (out[0] != 'h' || out[1] != 'e' || out[2] != 'l')
        {
            fail("wrong plain text in packet");
        }
        
        //
        // create a PBE encrypted message and read it back.
        //
        byte[]    text = { (byte)'h', (byte)'e', (byte)'l', (byte)'l', (byte)'o', (byte)' ', (byte)'w', (byte)'o', (byte)'r', (byte)'l', (byte)'d', (byte)'!', (byte)'\n' };
        
        //
        // encryption step - convert to literal data, compress, encode.
        //
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
                                                                PGPCompressedData.ZIP);
                                                                
        Date                       cDate = new Date((System.currentTimeMillis() / 1000) * 1000);
        PGPLiteralDataGenerator    lData = new PGPLiteralDataGenerator();
        OutputStream               comOut = comData.open(new UncloseableOutputStream(bOut));
        OutputStream               ldOut = lData.open(
            new UncloseableOutputStream(comOut),
            PGPLiteralData.BINARY, 
            PGPLiteralData.CONSOLE, 
            text.length,
            cDate);

        ldOut.write(text);

        ldOut.close();
        
        comOut.close();

        //
        // encrypt - with stream close
        //
        ByteArrayOutputStream        cbOut = new ByteArrayOutputStream();
        PGPEncryptedDataGenerator    cPk = new PGPEncryptedDataGenerator(PGPEncryptedData.CAST5, new SecureRandom(), "BC");
        
        cPk.addMethod(pass);
        
        OutputStream    cOut = cPk.open(new UncloseableOutputStream(cbOut), bOut.toByteArray().length);

        cOut.write(bOut.toByteArray());

        cOut.close();

        out = decryptMessage(cbOut.toByteArray(), cDate);

        if (!areEqual(out, text))
        {
            fail("wrong plain text in generated packet");
        }

        //
        // encrypt - with generator close
        //
        cbOut = new ByteArrayOutputStream();
        cPk = new PGPEncryptedDataGenerator(PGPEncryptedData.CAST5, new SecureRandom(), "BC");

        cPk.addMethod(pass);

        cOut = cPk.open(new UncloseableOutputStream(cbOut), bOut.toByteArray().length);

        cOut.write(bOut.toByteArray());

        cPk.close();

        out = decryptMessage(cbOut.toByteArray(), cDate);

        if (!areEqual(out, text))
        {
            fail("wrong plain text in generated packet");
        }

        //
        // encrypt - partial packet style.
        //
        SecureRandom    rand = new SecureRandom();
        byte[]    test = new byte[1233];
        
        rand.nextBytes(test);
        
        bOut = new ByteArrayOutputStream();
        
        comData = new PGPCompressedDataGenerator(
                                 PGPCompressedData.ZIP);
        comOut = comData.open(bOut);
        lData = new PGPLiteralDataGenerator();

        ldOut = lData.open(new UncloseableOutputStream(comOut),
            PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, TEST_DATE,
            new byte[16]);

        
        ldOut.write(test);

        ldOut.close();
        
        comOut.close();

        cbOut = new ByteArrayOutputStream();
        cPk = new PGPEncryptedDataGenerator(PGPEncryptedData.CAST5, rand, "BC");
        
        cPk.addMethod(pass);
        
        cOut = cPk.open(new UncloseableOutputStream(cbOut), new byte[16]);

        cOut.write(bOut.toByteArray());

        cOut.close();

        out = decryptMessage(cbOut.toByteArray(), TEST_DATE);
        if (!areEqual(out, test))
        {
            fail("wrong plain text in generated packet");
        }
        
        //
        // with integrity packet
        //
        cbOut = new ByteArrayOutputStream();
        cPk = new PGPEncryptedDataGenerator(PGPEncryptedData.CAST5, true, rand, "BC");
        
        cPk.addMethod(pass);
        
        cOut = cPk.open(new UncloseableOutputStream(cbOut), new byte[16]);

        cOut.write(bOut.toByteArray());

        cOut.close();

        out = decryptMessage(cbOut.toByteArray(), TEST_DATE);
        if (!areEqual(out, test))
        {
            fail("wrong plain text in generated packet");
        }
    }

    public String getName()
    {
        return "PGPPBETest";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PGPPBETest());
    }
}
