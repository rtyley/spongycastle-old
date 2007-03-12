package org.bouncycastle.jce.provider.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

/**
 * check that cipher input/output streams are working correctly
 */
public class CipherStreamTest
    extends SimpleTest
{
    public CipherStreamTest()
    {
    }

    private void runTest(
        String  name)
    {
        String lCode = "ABCDEFGHIJKLMNOPQRSTUVWXY0123456789";

        try
        {
            KeyGenerator            kGen;

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

            int c;

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
                fail("Failed - decrypted data doesn't match.");
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Failed - exception " + e.toString());
        }
    }

    private void testException(
        String  name)
    {
        try
        {
            byte[] keyBytes = {
                    (byte)128, (byte)131, (byte)133, (byte)134,
                    (byte)137, (byte)138, (byte)140, (byte)143,
                    (byte)128, (byte)131, (byte)133, (byte)134,
                    (byte)137, (byte)138, (byte)140, (byte)143 };

            SecretKeySpec cipherKey = new SecretKeySpec(keyBytes, name);
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
                
                fail("failed exception test - no ShortBufferException thrown");
            }
            catch (ShortBufferException e)
            {
                // ignore
            }
            
            try
            {
                Cipher c = Cipher.getInstance(name, "BC");
    
                Key k = new PublicKey()
                {

                    public String getAlgorithm()
                    {
                        return "STUB";
                    }

                    public String getFormat()
                    {
                        return null;
                    }

                    public byte[] getEncoded()
                    {
                        return null;
                    }
                    
                };
    
                c.init(Cipher.ENCRYPT_MODE, k);
    
                fail("failed exception test - no InvalidKeyException thrown for public key");
            }
            catch (InvalidKeyException e)
            {
                // okay
            }
            
            try
            {
                Cipher c = Cipher.getInstance(name, "BC");
    
                Key k = new PrivateKey()
                {

                    public String getAlgorithm()
                    {
                        return "STUB";
                    }

                    public String getFormat()
                    {
                        return null;
                    }

                    public byte[] getEncoded()
                    {
                        return null;
                    }
                    
                };
    
                c.init(Cipher.DECRYPT_MODE, k);
    
                fail("failed exception test - no InvalidKeyException thrown for private key");
            }
            catch (InvalidKeyException e)
            {
                // okay
            }
        }
        catch (Exception e)
        {
            fail("unexpected exception.", e);
        }
    }
    
    public void performTest()
    {
        runTest("RC4");
        testException("RC4");
        runTest("Salsa20");
        testException("Salsa20");
        runTest("DES/ECB/PKCS7Padding");
        runTest("DES/CFB8/NoPadding");
    }

    public String getName()
    {
        return "CipherStreamTest";
    }


    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new CipherStreamTest());
    }
}
