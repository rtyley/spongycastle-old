package org.bouncycastle.jce.provider.test;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.Security;

/**
 * basic test class for the AES cipher vectors from FIPS-197
 */
public class AESTest
    extends BaseBlockCipherTest
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

    public AESTest()
    {
        super("AES");
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
        
        wrapTest(1, "AESWrap", kek1, in1, out1);

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

        oidTest(oids, names, 4);


        String[] wrapOids = {
                NISTObjectIdentifiers.id_aes128_wrap.getId(),
                NISTObjectIdentifiers.id_aes192_wrap.getId(),
                NISTObjectIdentifiers.id_aes256_wrap.getId()
        };

        wrapOidTest(wrapOids, "AESWrap");
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new AESTest());
    }
}
