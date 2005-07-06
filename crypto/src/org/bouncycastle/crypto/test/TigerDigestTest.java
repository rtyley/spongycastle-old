package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.TigerDigest;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * Tiger Digest Test
 */
public class TigerDigestTest
    implements Test
{
    final static String[] messages = {
        "",
        "abc",
        "Tiger",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvw",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdefghijklmnopqrstuvwxyz+0123456789",
        "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge, 1996.",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-"
    };

    final static String[] digests = {
        "3293AC630C13F0245F92BBB1766E16167A4E58492DDE73F3",
        "2AAB1484E8C158F2BFB8C5FF41B57A525129131C957B5F93",
        "DD00230799F5009FEC6DEBC838BB6A27DF2B9D6F110C7937",
        "F71C8583902AFB879EDFE610F82C0D4786A3A534504486B5",
        "38F41D9D9A710A10C3727AC0DEEAA270727D9F926EC10139",
        "48CEEB6308B87D46E95D656112CDF18D97915F9765658957",
        "631ABDD103EB9A3D245B6DFD4D77B257FC7439501D1568DD",
        "C54034E5B43EB8005848A7E0AE6AAC76E4FF590AE715FD25",
        "C54034E5B43EB8005848A7E0AE6AAC76E4FF590AE715FD25"
    };

    final static String hash64k = "FDF4F5B35139F48E710E421BE5AF411DE1A8AAC333F26204";

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
        return "Tiger";
    }

    public TestResult perform()
    {
        Digest digest = new TigerDigest();
        byte[] resBuf = new byte[digest.getDigestSize()];
        int failCount = 0;

        for (int i = 0; i < messages.length; i++)
        {
            byte[] m = messages[i].getBytes();
            digest.update(m, 0, m.length);
            digest.doFinal(resBuf, 0);

            if (!arraysEqual(resBuf, Hex.decode(digests[i])))
            {
                return new SimpleTestResult(false, getName() + ": Vector " + i + " failed got " + new String(Hex.encode(resBuf)));
            }
        }

        //
        // test 2
        //
        byte[] m = messages[messages.length-1].getBytes();

        digest.update(m, 0, m.length/2);

        // clone the Digest
        Digest d = new TigerDigest((TigerDigest)digest);

        digest.update(m, m.length/2, m.length - m.length/2);
        digest.doFinal(resBuf, 0);

        if (!arraysEqual(resBuf, Hex.decode(digests[digests.length-1])))
        {
            return new SimpleTestResult(false,
                "Tiger failing clone test"
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
                "Tiger failing clone test - part 2"
                + System.getProperty("line.separator")
                + "    expected: " +  digests[digests.length-1]
                + System.getProperty("line.separator")
                + "    got     : " + new String(Hex.encode(resBuf)));
        }

        for (int i = 0; i < 65536; i++)
        {
            digest.update((byte)(i & 0xff));
        }
        digest.doFinal(resBuf, 0);

        if (!arraysEqual(resBuf, Hex.decode(hash64k)))
        {
            return new SimpleTestResult(false, getName() + ": Million a's failed");
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public static void main(
        String[]    args)
    {
        TigerDigestTest test = new TigerDigestTest();
        TestResult          result = test.perform();

        System.out.println(result);
    }
}
