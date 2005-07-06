package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.RIPEMD128Digest;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * RIPEMD128 Digest Test
 */
public class RIPEMD128DigestTest
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
        "cdf26213a150dc3ecb610f18f6b38b46",
        "86be7afa339d0fc7cfc785e72f578d33",
        "c14a12199c66e4ba84636b0f69144c77",
        "9e327b3d6e523062afc1132d7df9d1b8",
        "fd2aa607f71dc8f510714922b371834e",
        "a1aa0689d0fafa2ddc22e88b49133a06",
        "d1e959eb179c911faea4624c60c5c702",
        "3f45ef194732c2dbb2c4a2c769795fa3"
    };

    final static String million_a_digest = "4a7f5723f954eba1216c9d8f6320431f";

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
        return "RIPEMD128";
    }

    public TestResult perform()
    {
        Digest digest = new RIPEMD128Digest();
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
        Digest d = new RIPEMD128Digest((RIPEMD128Digest)digest);

        digest.update(m, m.length/2, m.length - m.length/2);
        digest.doFinal(resBuf, 0);

        if (!arraysEqual(resBuf, Hex.decode(digests[digests.length-1])))
        {
            return new SimpleTestResult(false,
                "RIPEMD128 failing clone test"
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
                "RIPEMD128 failing clone test - part 2"
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
        RIPEMD128DigestTest test = new RIPEMD128DigestTest();
        TestResult          result = test.perform();

        System.out.println(result);
    }
}
