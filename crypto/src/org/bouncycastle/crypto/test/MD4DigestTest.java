package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * standard vector test for MD4 from RFC 1320.
 */
public class MD4DigestTest
    implements Test
{
    static private String  testVec1 = "";
    static private String  resVec1 = "31d6cfe0d16ae931b73c59d7e0c089c0";

    static private String  testVec2 = "61";
    static private String  resVec2 = "bde52cb31de33e46245e05fbdbd6fb24";

    static private String  testVec3 = "616263";
    static private String  resVec3 = "a448017aaf21d8525fc10ae87aa6729d";

    static private String  testVec4 = "3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930";
    static private String  resVec4 = "e33b4ddc9c38f2199c3e7b164fcc0536";

    public String getName()
    {
        return "MD4";
    }

    public TestResult perform()
    {
        Digest  digest = new MD4Digest();
        byte[]  resBuf = new byte[digest.getDigestSize()];
        String  resStr;

        //
        // test 1
        //
        digest.doFinal(resBuf, 0);

        resStr = new String(Hex.encode(resBuf));
        if (!resVec1.equals(resStr))
        {
            return new SimpleTestResult(false,
                "MD4 failing standard vector test 1"
                + System.getProperty("line.separator")
                + "    expected: " + resVec1
                + System.getProperty("line.separator")
                + "    got     : " + resStr);
        }

        //
        // test 2
        //
        byte[]  bytes = Hex.decode(testVec2);

        digest.update(bytes, 0, bytes.length);

        digest.doFinal(resBuf, 0);

        resStr = new String(Hex.encode(resBuf));
        if (!resVec2.equals(resStr))
        {
            return new SimpleTestResult(false,
                "MD4 failing standard vector test 2"
                + System.getProperty("line.separator")
                + "    expected: " + resVec2
                + System.getProperty("line.separator")
                + "    got     : " + resStr);
        }

        //
        // test 3
        //
        bytes = Hex.decode(testVec3);

        digest.update(bytes, 0, bytes.length);

        digest.doFinal(resBuf, 0);

        resStr = new String(Hex.encode(resBuf));
        if (!resVec3.equals(resStr))
        {
            return new SimpleTestResult(false,
                "MD4 failing standard vector test 3"
                + System.getProperty("line.separator")
                + "    expected: " + resVec3
                + System.getProperty("line.separator")
                + "    got     : " + resStr);
        }

        //
        // test 4
        //
        bytes = Hex.decode(testVec4);

        digest.update(bytes, 0, bytes.length);

        digest.doFinal(resBuf, 0);

        resStr = new String(Hex.encode(resBuf));
        if (!resVec4.equals(resStr))
        {
            return new SimpleTestResult(false,
                "MD4 failing standard vector test 4"
                + System.getProperty("line.separator")
                + "    expected: " + resVec4
                + System.getProperty("line.separator")
                + "    got     : " + resStr);
        }

        //
        // test 5
        //
        bytes = Hex.decode(testVec4);

        digest.update(bytes, 0, bytes.length/2);

        // clone the Digest
        Digest d = new MD4Digest((MD4Digest)digest);

        digest.update(bytes, bytes.length/2, bytes.length - bytes.length/2);
        digest.doFinal(resBuf, 0);

        resStr = new String(Hex.encode(resBuf));
        if (!resVec4.equals(resStr))
        {
            return new SimpleTestResult(false,
                "MD4 failing standard vector test 5"
                + System.getProperty("line.separator")
                + "    expected: " + resVec4
                + System.getProperty("line.separator")
                + "    got     : " + resStr);
        }

        d.update(bytes, bytes.length/2, bytes.length - bytes.length/2);
        d.doFinal(resBuf, 0);

        resStr = new String(Hex.encode(resBuf));
        if (!resVec4.equals(resStr))
        {
            return new SimpleTestResult(false,
                "MD4 failing standard vector test 5"
                + System.getProperty("line.separator")
                + "    expected: " + resVec4
                + System.getProperty("line.separator")
                + "    got     : " + resStr);
        }
        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public static void main(
        String[]    args)
    {
        MD4DigestTest   test = new MD4DigestTest();
        TestResult      result = test.perform();

        System.out.println(result);
    }
}
