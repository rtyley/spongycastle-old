package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * check that cipher input/output streams are working correctly
 */
public class CipherStreamTest
    implements Test
{
    public CipherStreamTest()
    {
    }

    private TestResult runTest(
        String  name)
    {
        String lCode = "ABCDEFGHIJKLMNOPQRSTUVWXY0123456789";

        try
        {
            KeyGenerator            kGen = null;

            if (name.indexOf('/') < 0)
            {
                kGen = KeyGenerator.getInstance(name, "BC");
            }
            else
            {
                kGen = KeyGenerator.getInstance(name.substring(0, name.indexOf('/')), "BC");
            }

            Cipher                  in = Cipher.getInstance(name, "BC");
            Cipher                  out = Cipher.getInstance(name, "BC");
            Key                     key = kGen.generateKey();
            ByteArrayInputStream    bIn = new ByteArrayInputStream(lCode.getBytes());
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();

            in.init(Cipher.ENCRYPT_MODE, key);
            if (in.getIV() != null)
            {
                out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(in.getIV()));
            }
            else
            {
                out.init(Cipher.DECRYPT_MODE, key);
            }

            CipherInputStream       cIn = new CipherInputStream(bIn, in);
            CipherOutputStream      cOut = new CipherOutputStream(bOut, out);

            int c = 0;

            while ((c = cIn.read()) >= 0)
            {
                cOut.write(c);
            }

            cIn.close();

            cOut.flush();
            cOut.close();

            String  res = new String(bOut.toByteArray());

            if (!res.equals(lCode))
            {
                return new SimpleTestResult(false, getName() + ": Failed - decrypted data doesn't match.");
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": Failed - exception " + e.toString());
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    private TestResult testException(
        String  name)
    {
        String lCode = "ABCDEFGHIJKLMNOPQRSTUVWXY0123456789";
        
        try
        {
            byte[] rc4Key = { (byte)128, (byte)131, (byte)133, (byte)134,
                    (byte)137, (byte)138, (byte)140, (byte)143 };

            SecretKeySpec cipherKey = new SecretKeySpec(rc4Key, name);
            Cipher ecipher = Cipher.getInstance(name, "BC");
            ecipher.init(Cipher.ENCRYPT_MODE, cipherKey);

            byte[] cipherText = new byte[0];
            try
            {
                // According specification Method engineUpdate(byte[] input,
                // int inputOffset, int inputLen, byte[] output, int
                // outputOffset)
                // throws ShortBufferException - if the given output buffer is
                // too
                // small to hold the result
                ecipher.update(new byte[20], 0, 20, cipherText);
                
                return new SimpleTestResult(false, getName() + ": failed exception test - no ShortBufferException thrown");
            }
            catch (ShortBufferException e)
            {
                // ignore
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": unexpected exception.", e);
        }
        
        return new SimpleTestResult(true, getName() + ": Okay");
    }
    
    public TestResult perform()
    {
        TestResult  res = runTest("RC4");
        if (!res.isSuccessful())
        {
            return res;
        }

        res = testException("RC4");
        if (!res.isSuccessful())
        {
            return res;
        }
        
        res = runTest("DES/ECB/PKCS7Padding");
        if (!res.isSuccessful())
        {
            return res;
        }

        res = runTest("DES/CFB8/NoPadding");
        if (!res.isSuccessful())
        {
            return res;
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public String getName()
    {
        return "CipherStreamTest";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new CipherStreamTest();
        TestResult      result = test.perform();

        System.out.println(result.toString());
    }
}
