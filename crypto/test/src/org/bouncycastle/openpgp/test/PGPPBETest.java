package org.bouncycastle.openpgp.test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class PGPPBETest implements Test
{
    byte[] enc1 = Base64.decode(
            "jA0EAwMC5M5wWBP2HBZgySvUwWFAmMRLn7dWiZN6AkQMvpE3b6qwN3SSun7zInw2"
          + "hxxdgFzVGfbjuB8w");

    byte[] enc1crc = Base64.decode("H66L");

    char[] pass = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd' };

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

    /**
     * decrypt the passed in message stream
     */
    private byte[] decryptMessage(
        byte[]    message)
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
            throw new RuntimeException("wrong filename in packet");
        }

        InputStream              unc = ld.getInputStream();
        int                      ch;
        
        while ((ch = unc.read()) >= 0)
        {
            bOut.write(ch);
        }

        return bOut.toByteArray();
    }

    public TestResult perform()
    {
        try
        {
            byte[] out = decryptMessage(enc1);

            if (out[0] != 'h' || out[1] != 'e' || out[2] != 'l')
            {
                return new SimpleTestResult(false, getName() + ": wrong plain text in packet");
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
                                                                    
            PGPLiteralDataGenerator    lData = new PGPLiteralDataGenerator();

            OutputStream    ldOut = lData.open(comData.open(bOut),
                                                  PGPLiteralData.BINARY, 
                                                  PGPLiteralData.CONSOLE, 
                                                  text.length,
                                                  new Date());
            
            ldOut.write(text);

            lData.close();
            
            comData.close();

            //
            // encrypt
            //
            ByteArrayOutputStream        cbOut = new ByteArrayOutputStream();
            PGPEncryptedDataGenerator    cPk = new PGPEncryptedDataGenerator(PGPEncryptedData.CAST5, new SecureRandom(), "BC");
            
            cPk.addMethod(pass);
            
            OutputStream    cOut = cPk.open(cbOut, bOut.toByteArray().length);

            cOut.write(bOut.toByteArray());

            cOut.close();

            out = decryptMessage(cbOut.toByteArray());

            if (notEqual(out, text))
            {
                return new SimpleTestResult(false, getName() + ": wrong plain text in generated packet");
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
                                                                    
            lData = new PGPLiteralDataGenerator();

            ldOut = lData.open(comData.open(bOut),
                                     PGPLiteralData.BINARY, 
                                     PGPLiteralData.CONSOLE, 
                                     new Date(),
                                     new byte[16]);

            
            ldOut.write(test);

            lData.close();
            
            comData.close();

            cbOut = new ByteArrayOutputStream();
            cPk = new PGPEncryptedDataGenerator(PGPEncryptedData.CAST5, rand, "BC");
            
            cPk.addMethod(pass);
            
            cOut = cPk.open(cbOut, new byte[16]);

            cOut.write(bOut.toByteArray());

            cPk.close();

            out = decryptMessage(cbOut.toByteArray());
            if (notEqual(out, test))
            {
                return new SimpleTestResult(false, getName() + ": wrong plain text in generated packet");
            }
            
            //
            // with integrity packet
            //
            cbOut = new ByteArrayOutputStream();
            cPk = new PGPEncryptedDataGenerator(PGPEncryptedData.CAST5, true, rand, "BC");
            
            cPk.addMethod(pass);
            
            cOut = cPk.open(cbOut, new byte[16]);

            cOut.write(bOut.toByteArray());

            cPk.close();

            out = decryptMessage(cbOut.toByteArray());
            if (notEqual(out, test))
            {
                return new SimpleTestResult(false, getName() + ": wrong plain text in generated packet");
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
        return "PGPPBETest";
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test test = new PGPPBETest();
        TestResult result = test.perform();

        System.out.println(result.toString());
    }
}
