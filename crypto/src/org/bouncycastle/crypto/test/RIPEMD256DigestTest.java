package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.RIPEMD256Digest;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * RIPEMD128 Digest Test
 */
public class RIPEMD256DigestTest
    implements Test
{
    final static String[] messages = {
        "",
        "a",
        "abc",
        "message digest",
        "abcdefghijklmnopqrstuvwxyz",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
    };

    final static String[] digests = {
        "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d",
        "f9333e45d857f5d90a91bab70a1eba0cfb1be4b0783c9acfcd883a9134692925",
        "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65",
        "87e971759a1ce47a514d5c914c392c9018c7c46bc14465554afcdf54a5070c0e",
        "649d3034751ea216776bf9a18acc81bc7896118a5197968782dd1fd97d8d5133",
        "3843045583aac6c8c8d9128573e7a9809afb2a0f34ccc36ea9e72f16f6368e3f",
        "5740a408ac16b720b84424ae931cbb1fe363d1d0bf4017f1a89f7ea6de77a0b8",
        "06fdcc7a409548aaf91368c06a6275b553e3f099bf0ea4edfd6778df89a890dd"
    };

    final static String million_a_digest = "ac953744e10e31514c150d4d8d7b677342e33399788296e43ae4850ce4f97978";

    public static boolean arraysEqual(byte[] a, byte[] b)
    {
        if (a == b) return true;
        if (a.length != b.length) return false;

        for (int i = 0; i < a.length; i++)
        {
            if (a[i] != b[i]) return false;
        }

        return true;
    }
        
    public String getName()
    {
        return "RIPEMD256";
    }

    public TestResult perform()
    {
        Digest digest = new RIPEMD256Digest();
        byte[] resBuf = new byte[digest.getDigestSize()];

        for (int i = 0; i < messages.length; i++)
        {
            byte[] m = messages[i].getBytes();
            digest.update(m, 0, m.length);
            digest.doFinal(resBuf, 0);

            if (!arraysEqual(resBuf, Hex.decode(digests[i])))
            {
                return new SimpleTestResult(false, getName() + ": Vector " + i + " failed");
            }
        }

        //
        // test 2
        //
        byte[] m = messages[messages.length-1].getBytes();

        digest.update(m, 0, m.length/2);

        // clone the Digest
        Digest d = new RIPEMD256Digest((RIPEMD256Digest)digest);

        digest.update(m, m.length/2, m.length - m.length/2);
        digest.doFinal(resBuf, 0);

        if (!arraysEqual(resBuf, Hex.decode(digests[digests.length-1])))
        {
            return new SimpleTestResult(false,
                "RIPEMD256 failing clone test"
                + System.getProperty("line.separator")
                + "    expected: " + digests[digests.length-1]
                + System.getProperty("line.separator")
                + "    got     : " + new String(Hex.encode(resBuf)));
        }

        d.update(m, m.length/2, m.length - m.length/2);
        d.doFinal(resBuf, 0);

        if (!arraysEqual(resBuf, Hex.decode(digests[digests.length-1])))
        {
            return new SimpleTestResult(false,
                "RIPEMD256 failing clone test - part 2"
                + System.getProperty("line.separator")
                + "    expected: " +  digests[digests.length-1]
                + System.getProperty("line.separator")
                + "    got     : " + new String(Hex.encode(resBuf)));
        }

        for (int i = 0; i < 1000000; i++)
        {
            digest.update((byte)'a');
        }
        digest.doFinal(resBuf, 0);

        if (!arraysEqual(resBuf, Hex.decode(million_a_digest)))
        {
            return new SimpleTestResult(false, getName() + ": Million a's failed");
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public static void main(
        String[]    args)
    {
        RIPEMD256DigestTest test = new RIPEMD256DigestTest();
        TestResult          result = test.perform();

        System.out.println(result);
    }
}
