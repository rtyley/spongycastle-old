package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * RIPEMD160 Digest Test
 */
public class RIPEMD160DigestTest
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
        "9c1185a5c5e9fc54612808977ee8f548b2258d31",
        "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",
        "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
        "5d0689ef49d2fae572b881b123a85ffa21595f36",
        "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
        "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
        "b0e20b6e3116640286ed3a87a5713079b21f5189",
        "9b752e45573d4b39f4dbd3323cab82bf63326bfb"
    };

    final static String million_a_digest = "52783243c1697bdbe16d37f97f68f08325dc1528";

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
        return "RIPEMD160";
    }

    public TestResult perform()
    {
        Digest digest = new RIPEMD160Digest();
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
        Digest d = new RIPEMD160Digest((RIPEMD160Digest)digest);

        digest.update(m, m.length/2, m.length - m.length/2);
        digest.doFinal(resBuf, 0);

        if (!arraysEqual(resBuf, Hex.decode(digests[digests.length-1])))
        {
            return new SimpleTestResult(false,
                "RIPEMD160 failing clone test"
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
                "RIPEMD160 failing clone test - part 2"
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
        RIPEMD160DigestTest test = new RIPEMD160DigestTest();
        TestResult          result = test.perform();

        System.out.println(result);
    }
}
