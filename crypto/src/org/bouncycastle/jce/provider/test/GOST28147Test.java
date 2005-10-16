package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * basic test class for the GOST28147 cipher
 */
public class GOST28147Test
         implements Test
{
        static String[] cipherTests =
        {
            "256",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "4e6f77206973207468652074696d6520666f7220616c6c20",
            "281630d0d5770030068c252d841e84149ccc1912052dbc02",

            "256",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "4e6f77206973207468652074696d65208a920c6ed1a804f5",
            "88e543dfc04dc4f764fa7b624741cec07de49b007bf36065"
        };

        public String getName()
        {
            return "GOST28147";
        }

        private boolean equalArray(
            byte[]  a,
            byte[]  b)
        {
            if (a.length != b.length)
            {
                return false;
            }

            for (int i = 0; i != a.length; i++)
            {
                if (a[i] != b[i])
                {
                    return false;
                }
            }

            return true;
        }

        public TestResult testECB(
            int         strength,
            byte[]      keyBytes,
            byte[]      input,
            byte[]      output)
        {
            Key                     key;
            Cipher                  in, out;
            CipherInputStream       cIn;
            CipherOutputStream      cOut;
            ByteArrayInputStream    bIn;
            ByteArrayOutputStream   bOut;

            try
            {
                key = new SecretKeySpec(keyBytes, "GOST28147");

                in = Cipher.getInstance("GOST28147/ECB/NoPadding", "BC");
                out = Cipher.getInstance("GOST28147/ECB/NoPadding", "BC");
                out.init(Cipher.ENCRYPT_MODE, key);
            }
            catch (Exception e)
            {
                return new SimpleTestResult(false, getName() + ": GOST28147 failed initialisation - " + e.toString());
            }

            try
            {
                in.init(Cipher.DECRYPT_MODE, key);
            }
            catch (Exception e)
            {
                return new SimpleTestResult(false, getName() + ": GOST28147 failed initialisation - " + e.toString());
            }

            //
            // encryption pass
            //
            bOut = new ByteArrayOutputStream();

            cOut = new CipherOutputStream(bOut, out);

            try
            {
                for (int i = 0; i != input.length / 2; i++)
                {
                    cOut.write(input[i]);
                }
                cOut.write(input, input.length / 2, input.length - input.length / 2);
                cOut.close();
            }
            catch (IOException e)
            {
                return new SimpleTestResult(false, getName() + ": GOST28147 failed encryption - " + e.toString());
            }

            byte[]    bytes;

            bytes = bOut.toByteArray();

            if (!equalArray(bytes, output))
            {
                return new SimpleTestResult(false, getName() + ": GOST28147 failed encryption - expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(bytes)));
            }

            //
            // decryption pass
            //
            bIn = new ByteArrayInputStream(bytes);

            cIn = new CipherInputStream(bIn, in);

            try
            {
                DataInputStream dIn = new DataInputStream(cIn);

                bytes = new byte[input.length];

                for (int i = 0; i != input.length / 2; i++)
                {
                    bytes[i] = (byte)dIn.read();
                }
                dIn.readFully(bytes, input.length / 2, bytes.length - input.length / 2);
            }
            catch (Exception e)
            {
                return new SimpleTestResult(false, getName() + ": GOST28147 failed encryption - " + e.toString());
            }

            if (!equalArray(bytes, input))
            {
                return new SimpleTestResult(false, getName() + ": GOST28147 failed decryption - expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(bytes)));
            }

            return new SimpleTestResult(true, getName() + ": GOST28147 Okay");
        }

    public TestResult testCFB(
        int         strength,
        byte[]      keyBytes,
        byte[]      input,
        byte[]      output)
    {
        Key                     key;
        Cipher                  in, out;
        CipherInputStream       cIn;
        CipherOutputStream      cOut;
        ByteArrayInputStream    bIn;
        ByteArrayOutputStream   bOut;

        try
        {
            key = new SecretKeySpec(keyBytes, "GOST28147");

            in = Cipher.getInstance("GOST28147/CFB8/NoPadding", "BC");
            out = Cipher.getInstance("GOST28147/CFB8/NoPadding", "BC");
            byte[] iv = {1,2,3,4,5,6,7,8};
            out.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": GOST28147 failed initialisation - " + e.toString(), e);
        }

        try
        {
            byte[] iv = {1,2,3,4,5,6,7,8};
            in.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": GOST28147 failed initialisation - " + e.toString(), e);
        }

        //
        // encryption pass
        //
        bOut = new ByteArrayOutputStream();

        cOut = new CipherOutputStream(bOut, out);

        try
        {
            for (int i = 0; i != input.length / 2; i++)
            {
                cOut.write(input[i]);
            }
            cOut.write(input, input.length / 2, input.length - input.length / 2);
            cOut.close();
        }
        catch (IOException e)
        {
            return new SimpleTestResult(false, getName() + ": GOST28147 failed encryption - " + e.toString(), e);
        }

        byte[]    bytes;

        bytes = bOut.toByteArray();

        if (!equalArray(bytes, output))
        {
            return new SimpleTestResult(false, getName() + ": GOST28147 failed encryption - expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(bytes)));
        }

        //
        // decryption pass
        //
        bIn = new ByteArrayInputStream(bytes);

        cIn = new CipherInputStream(bIn, in);

        try
        {
            DataInputStream dIn = new DataInputStream(cIn);

            bytes = new byte[input.length];

            for (int i = 0; i != input.length / 2; i++)
            {
                bytes[i] = (byte)dIn.read();
            }
            dIn.readFully(bytes, input.length / 2, bytes.length - input.length / 2);
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": GOST28147 failed encryption - " + e.toString(), e);
        }

        if (!equalArray(bytes, input))
        {
            return new SimpleTestResult(false, getName() + ": GOST28147 failed decryption - expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(bytes)));
        }

        return new SimpleTestResult(true, getName() + ": GOST28147 Okay");
    }

    private TestResult oidTest()
    {
        String[] oids = {
                CryptoProObjectIdentifiers.gostR28147_cbc.getId(),
        };
        
        String[] names = {
            "GOST28147/CBC/PKCS7Padding"
        };
        
        try
        {
            
            byte[]          data = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            IvParameterSpec ivSpec = new IvParameterSpec(new byte[8]);
            
            for (int i = 0; i != oids.length; i++)
            {
                Cipher c1 = Cipher.getInstance(oids[i], "BC");
                Cipher c2 = Cipher.getInstance(names[i], "BC");
                KeyGenerator kg = KeyGenerator.getInstance(oids[i], "BC");
                
                SecretKey k = kg.generateKey();
                
                c1.init(Cipher.ENCRYPT_MODE, k, ivSpec);
                c2.init(Cipher.DECRYPT_MODE, k, ivSpec);

                byte[] result = c2.doFinal(c1.doFinal(data));

                if (!equalArray(data, result))
                {
                    return new SimpleTestResult(false, getName() + ": failed OID test");
                }
            }
        }
        catch (Exception ex)
        {
            return new SimpleTestResult(false, getName() + ": failed exception " + ex.toString(), ex);
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }
    
        public TestResult perform()
        {
            TestResult  result;

            for (int i = 0; i != cipherTests.length; i += 8)
            {
                result = testECB(Integer.parseInt(cipherTests[i]),
                                Hex.decode(cipherTests[i + 1]),
                                Hex.decode(cipherTests[i + 2]),
                                Hex.decode(cipherTests[i + 3]));

                if (!result.isSuccessful())
                {
                    return result;
                }

                result = testCFB(Integer.parseInt(cipherTests[i + 4]),
                                Hex.decode(cipherTests[i + 4 + 1]),
                                Hex.decode(cipherTests[i + 4 + 2]),
                                Hex.decode(cipherTests[i + 4 + 3]));

                if (!result.isSuccessful())
                {
                    return result;
                }
                
                result = oidTest();
                if (!result.isSuccessful())
                {
                    return result;
                }

            }
            return new SimpleTestResult(true, getName() + ": Okay");
        }

        public static void main(
            String[]    args)
        {
            Security.addProvider(new BouncyCastleProvider());

            Test            test = new GOST28147Test();
            TestResult      result = test.perform();

            System.out.println(result.toString());
        }
    }
