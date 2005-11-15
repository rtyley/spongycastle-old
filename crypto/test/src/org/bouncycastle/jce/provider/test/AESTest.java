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
import org.bouncycastle.util.test.SimpleTest;

/**
 * basic test class for the AES cipher vectors from FIPS-197
 */
public class AESTest
    extends SimpleTest
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

    public void test(
        int         strength,
        byte[]      keyBytes,
        byte[]      input,
        byte[]      output)
        throws Exception
    {
        Key                     key;
        Cipher                  in, out;
        CipherInputStream       cIn;
        CipherOutputStream      cOut;
        ByteArrayInputStream    bIn;
        ByteArrayOutputStream   bOut;

        key = new SecretKeySpec(keyBytes, "AES");

        in = Cipher.getInstance("AES/ECB/NoPadding", "BC");
        out = Cipher.getInstance("AES/ECB/NoPadding", "BC");
        
        try
        {
            out.init(Cipher.ENCRYPT_MODE, key);
        }
        catch (Exception e)
        {
            fail("AES failed initialisation - " + e.toString(), e);
        }

        try
        {
            in.init(Cipher.DECRYPT_MODE, key);
        }
        catch (Exception e)
        {
            fail("AES failed initialisation - " + e.toString(), e);
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
            fail("AES failed encryption - " + e.toString(), e);
        }

        byte[]    bytes;

        bytes = bOut.toByteArray();

        if (!areEqual(bytes, output))
        {
            fail("AES failed encryption - expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(bytes)));
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
            fail("AES failed encryption - " + e.toString(), e);
        }

        if (!areEqual(bytes, input))
        {
            fail("AES failed decryption - expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(bytes)));
        }
    }

    private void wrapTest(
        int     id,
        byte[]  kek,
        byte[]  in,
        byte[]  out)
        throws Exception
    {
        Cipher wrapper = Cipher.getInstance("AESWrap", "BC");

        wrapper.init(Cipher.WRAP_MODE, new SecretKeySpec(kek, "AES"));

        try
        {
            byte[]  cText = wrapper.wrap(new SecretKeySpec(in, "AES"));
            if (!areEqual(cText, out))
            {
                fail("failed wrap test " + id  + " expected " + new String(Hex.encode(out)) + " got " + new String(Hex.encode(cText)));
            }
        }
        catch (Exception e)
        {
            fail("failed wrap test exception " + e.toString(), e);
        }

        wrapper.init(Cipher.UNWRAP_MODE, new SecretKeySpec(kek, "AES"));

        try
        {
            Key  pText = wrapper.unwrap(out, "AES", Cipher.SECRET_KEY);
            if (!areEqual(pText.getEncoded(), in))
            {
                fail("failed unwrap test " + id  + " expected " + new String(Hex.encode(in)) + " got " + new String(Hex.encode(pText.getEncoded())));
            }
        }
        catch (Exception e)
        {
            fail("failed unwrap test exception " + e.toString(), e);
        }
    }

    private void oidTest()
        throws Exception
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
            
            if (!areEqual(data, result))
            {
                fail("failed OID test");
            }
            
            if (k.getEncoded().length != (16 + ((i / 4) * 8)))
            {
                fail("failed key length test");
            }
        }
    }

    public void performTest()
        throws Exception
    {
        for (int i = 0; i != cipherTests.length; i += 4)
        {
            test(Integer.parseInt(cipherTests[i]), 
                            Hex.decode(cipherTests[i + 1]),
                            Hex.decode(cipherTests[i + 2]),
                            Hex.decode(cipherTests[i + 3]));
        }

        byte[]  kek1 = Hex.decode("000102030405060708090a0b0c0d0e0f");
        byte[]  in1 = Hex.decode("00112233445566778899aabbccddeeff");
        byte[]  out1 = Hex.decode("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5");
        
        wrapTest(1, kek1, in1, out1);

        oidTest();
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new AESTest());
    }
}
