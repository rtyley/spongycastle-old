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
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * basic test class for the AES cipher vectors from FIPS-197
 */
public class AESTest
    implements Test
{
    static String[] cipherTests =
    {
        "128",
        "000102030405060708090a0b0c0d0e0f",
        "00112233445566778899aabbccddeeff",
        "69c4e0d86a7b0430d8cdb78070b4c55a",
        "192",
        "000102030405060708090a0b0c0d0e0f1011121314151617",
        "00112233445566778899aabbccddeeff",
        "dda97ca4864cdfe06eaf70a0ec0d7191",
        "256",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "00112233445566778899aabbccddeeff",
        "8ea2b7ca516745bfeafc49904b496089",
    };

    public String getName()
    {
        return "AES";
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

    public TestResult test(
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
            key = new SecretKeySpec(keyBytes, "AES");

            in = Cipher.getInstance("AES/ECB/NoPadding", "BC");
            out = Cipher.getInstance("AES/ECB/NoPadding", "BC");

            out.init(Cipher.ENCRYPT_MODE, key);
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": AES failed initialisation - " + e.toString(), e);
        }

        try
        {
            in.init(Cipher.DECRYPT_MODE, key);
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": AES failed initialisation - " + e.toString(), e);
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
            return new SimpleTestResult(false, getName() + ": AES failed encryption - " + e.toString(), e);
        }

        byte[]    bytes;

        bytes = bOut.toByteArray();

        if (!equalArray(bytes, output))
        {
            return new SimpleTestResult(false, getName() + ": AES failed encryption - expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(bytes)));
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
            return new SimpleTestResult(false, getName() + ": AES failed encryption - " + e.toString(), e);
        }

        if (!equalArray(bytes, input))
        {
            return new SimpleTestResult(false, getName() + ": AES failed decryption - expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(bytes)));
        }

        return new SimpleTestResult(true, getName() + ": AES Okay");
    }

    private TestResult wrapTest(
        int     id,
        byte[]  kek,
        byte[]  in,
        byte[]  out)
    {
        try
        {
            Cipher wrapper = Cipher.getInstance("AESWrap", "BC");

            wrapper.init(Cipher.WRAP_MODE, new SecretKeySpec(kek, "AES"));

            try
            {
                byte[]  cText = wrapper.wrap(new SecretKeySpec(in, "AES"));
                if (!equalArray(cText, out))
                {
                    return new SimpleTestResult(false, getName() + ": failed wrap test " + id  + " expected " + new String(Hex.encode(out)) + " got " + new String(Hex.encode(cText)));
                }
            }
            catch (Exception e)
            {
                e.printStackTrace();
                return new SimpleTestResult(false, getName() + ": failed wrap test exception " + e.toString(), e);
            }

            wrapper.init(Cipher.UNWRAP_MODE, new SecretKeySpec(kek, "AES"));

            try
            {
                Key  pText = wrapper.unwrap(out, "AES", Cipher.SECRET_KEY);
                if (!equalArray(pText.getEncoded(), in))
                {
                    return new SimpleTestResult(false, getName() + ": failed unwrap test " + id  + " expected " + new String(Hex.encode(in)) + " got " + new String(Hex.encode(pText.getEncoded())));
                }
            }
            catch (Exception e)
            {
                return new SimpleTestResult(false, getName() + ": failed unwrap test exception " + e.toString(), e);
            }
        }
        catch (Exception ex)
        {
            return new SimpleTestResult(false, getName() + ": failed exception " + ex.toString(), ex);
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    private TestResult oidTest()
    {
        String[] oids = {
                NISTObjectIdentifiers.id_aes128_ECB.getId(),
                NISTObjectIdentifiers.id_aes128_CBC.getId(),
                NISTObjectIdentifiers.id_aes128_OFB.getId(),
                NISTObjectIdentifiers.id_aes128_CFB.getId(),
                NISTObjectIdentifiers.id_aes192_ECB.getId(),
                NISTObjectIdentifiers.id_aes192_CBC.getId(),
                NISTObjectIdentifiers.id_aes192_OFB.getId(),
                NISTObjectIdentifiers.id_aes192_CFB.getId(),
                NISTObjectIdentifiers.id_aes256_ECB.getId(),
                NISTObjectIdentifiers.id_aes256_CBC.getId(),
                NISTObjectIdentifiers.id_aes256_OFB.getId(),
                NISTObjectIdentifiers.id_aes256_CFB.getId()
        };
        
        String[] names = {
                "AES/ECB/PKCS7Padding",
                "AES/CBC/PKCS7Padding",
                "AES/OFB/PKCS7Padding",
                "AES/CFB/PKCS7Padding",
                "AES/ECB/PKCS7Padding",
                "AES/CBC/PKCS7Padding",
                "AES/OFB/PKCS7Padding",
                "AES/CFB/PKCS7Padding",
                "AES/ECB/PKCS7Padding",
                "AES/CBC/PKCS7Padding",
                "AES/OFB/PKCS7Padding",
                "AES/CFB/PKCS7Padding"
        };
        
        try
        {
            
            byte[]          data = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
            
            for (int i = 0; i != oids.length; i++)
            {
                Cipher c1 = Cipher.getInstance(oids[i], "BC");
                Cipher c2 = Cipher.getInstance(names[i], "BC");
                KeyGenerator kg = KeyGenerator.getInstance(oids[i], "BC");
                
                SecretKey k = kg.generateKey();
                
                if (names[i].startsWith("AES/ECB"))
                {
                    c1.init(Cipher.ENCRYPT_MODE, k);
                    c2.init(Cipher.DECRYPT_MODE, k);
                }
                else
                {
                    c1.init(Cipher.ENCRYPT_MODE, k, ivSpec);
                    c2.init(Cipher.DECRYPT_MODE, k, ivSpec);
                }

                byte[] result = c2.doFinal(c1.doFinal(data));
                
                if (!equalArray(data, result))
                {
                    return new SimpleTestResult(false, getName() + ": failed OID test");
                }
                
                if (k.getEncoded().length != (16 + ((i / 4) * 8)))
                {
                    return new SimpleTestResult(false, getName() + ": failed key length test");
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

        for (int i = 0; i != cipherTests.length; i += 4)
        {
            result = test(Integer.parseInt(cipherTests[i]), 
                            Hex.decode(cipherTests[i + 1]),
                            Hex.decode(cipherTests[i + 2]),
                            Hex.decode(cipherTests[i + 3]));

            if (!result.isSuccessful())
            {
                return result;
            }
        }

        byte[]  kek1 = Hex.decode("000102030405060708090a0b0c0d0e0f");
        byte[]  in1 = Hex.decode("00112233445566778899aabbccddeeff");
        byte[]  out1 = Hex.decode("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5");
        result = wrapTest(1, kek1, in1, out1);
        if (!result.isSuccessful())
        {
            return result;
        }

        result = oidTest();
        if (!result.isSuccessful())
        {
            return result;
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new AESTest();
        TestResult      result = test.perform();

        System.out.println(result.toString());
    }
}
